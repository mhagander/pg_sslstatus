/*
 * pg_sslstatus.c - view status of all SSL connected backends from a central
 *                  point.
 *
 * Copyright (C) 2014 Redpill Linpro AB
 *
 * Licensed under the PostgreSQL License
 */

#include "postgres.h"
#include "funcapi.h"
#include "libpq/auth.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include "access/htup_details.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);
Datum pg_get_sslstatus(PG_FUNCTION_ARGS);

static void pg_sslstatus_shmem_hook(void);
static void pg_sslstatus_cauth_hook(Port *port, int status);
static void sslstatus_shmem_exit(int code, Datum arg);
static char *X509_NAME_to_cstring(X509_NAME *name);

static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;

typedef struct
{
	pid_t	pid;
	bool    ssl;
	int		bits;
	bool	compression;
	char    version[16];
	char    cipher[64];
	char    client_dn[64]; /* Empty if no client cert */
} SslInfoStruct;

typedef struct
{
    /* Modifications protected by AddinShmemInitLock */
	LWLockId		lock;
	Size			size;
	/* Modifications protected by lock above */
	SslInfoStruct	info[0];
} SslGlobalStatus;

SslGlobalStatus *sslstatus = NULL;

/*
 * Module load callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		return;

	/*
	 * We don't have access to MaxBackends yet, so we're just going to
	 * assume a total of less than 1000. If it were to go above that we
	 * will get an allocation failure later, so that shouldn't be too
	 * unsafe.
	 */
	RequestAddinShmemSpace(1000 * sizeof(SslInfoStruct));
	RequestAddinLWLocks(1);

	/*
	 * Install hooks.
	 */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pg_sslstatus_shmem_hook;

	prev_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = pg_sslstatus_cauth_hook;
}

void
_PG_fini(void)
{
	shmem_startup_hook = prev_shmem_startup_hook;
	ClientAuthentication_hook = prev_client_auth_hook;
}

static void
pg_sslstatus_shmem_hook(void)
{
	bool found;
	Size size;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	size = sizeof(SslGlobalStatus) + MaxBackends * sizeof(SslInfoStruct);
	sslstatus = ShmemInitStruct("pg_sslstatus", size, &found);
	if (!found)
	{
		memset(sslstatus, 0, size);
		sslstatus->size = size;
		sslstatus->lock = LWLockAssign();
	}

	LWLockRelease(AddinShmemInitLock);
}


static void
pg_sslstatus_cauth_hook(Port *port, int status)
{
	SSL *ssl;
	SslInfoStruct s;

	if (prev_client_auth_hook)
		(*prev_client_auth_hook) (port, status);

	/*
	 * We don't care about the authentication, but this is a good
	 * place to hook in to get the SSL status, as we know the
	 * connection has been established, and in the event that SSL
	 * client certificates are used, the information has been
	 * processed.
	 */

	ssl = MyProcPort->ssl;
	/*
	 * Store results in a local copy and memcpy() it over later to minimize
	 * the time the lock is held. In particular, X509 calls into OpenSSL
	 * can be scary... :)
	 */
	s.pid = MyProcPid;
	s.ssl = (ssl != NULL);
	if (ssl)
	{
		SSL_get_cipher_bits(ssl, &s.bits);
		s.compression = (SSL_get_current_compression(ssl) != NULL);
		strlcpy(s.version, SSL_get_version(ssl), sizeof(s.version));
		strlcpy(s.cipher, SSL_get_cipher(ssl), sizeof(s.cipher));
		if (MyProcPort->peer)
			strlcpy(s.client_dn,
					X509_NAME_to_cstring(X509_get_subject_name(MyProcPort->peer)),
					sizeof(s.client_dn));
		else
			s.client_dn[0] = '\0';
	}

	LWLockAcquire(sslstatus->lock, LW_EXCLUSIVE);
	memcpy(&sslstatus->info[MyBackendId], &s, sizeof(s));
	LWLockRelease(sslstatus->lock);

	on_shmem_exit(sslstatus_shmem_exit, 0);
}


static void
sslstatus_shmem_exit(int code, Datum arg)
{
	/*
	 * Only reset the pid, since that will make the record excluded by the SRF
	 * so there's no need to clear the rest.
	 */
	LWLockAcquire(sslstatus->lock, LW_EXCLUSIVE);
	sslstatus->info[MyBackendId].pid = -1;
	LWLockRelease(sslstatus->lock);
}





/*
 * Now for the SQL interface functions
 */

typedef struct
{
	int currslot;
	SslInfoStruct info[0];
} FctxStruct;

PG_FUNCTION_INFO_V1(pg_get_sslstatus);
Datum
pg_get_sslstatus(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	FctxStruct *ctxinfo;

	if (!sslstatus)
		ereport(ERROR,
				(errmsg("sslstatus is not initialized"),
				 (errhint("did you perhaps forget to add pg_sslstatus to shared_preload_libraries?"))));
	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		TupleDesc	tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		tupdesc = CreateTemplateTupleDesc(7, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "pid", INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "ssl", BOOLOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "bits", INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 4, "compression", BOOLOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 5, "version", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 6, "cipher", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 7, "clientdn", TEXTOID, -1, 0);

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/* Set up cross-call structure to hold our data throughout one execution */
		funcctx->user_fctx = palloc(sizeof(FctxStruct) + sslstatus->size);
		ctxinfo = (FctxStruct *)funcctx->user_fctx;
		ctxinfo->currslot = 0;

		/*
		 * Get a local copy of the status array so we don't have to hold it locked
		 * any longer than necessary.
		 */
		LWLockAcquire(sslstatus->lock, LW_EXCLUSIVE);
		memcpy(&ctxinfo->info, &sslstatus->info, sslstatus->size);
		LWLockRelease(sslstatus->lock);

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	ctxinfo = (FctxStruct *)funcctx->user_fctx;

	while (ctxinfo->currslot < MaxBackends)
	{
		SslInfoStruct *s;

		s = &ctxinfo->info[ctxinfo->currslot];
		if (s->pid > 0)
		{
			/* Something to return */
			Datum		values[7];
			bool		nulls[7];
			HeapTuple	tuple;

			MemSet(values, 0, sizeof(values));
			MemSet(nulls, 0, sizeof(nulls));

			values[0] = Int32GetDatum(s->pid);
			values[1] = BoolGetDatum(s->ssl);
			if (s->ssl)
			{
				values[2] = Int32GetDatum(s->bits);
				values[3] = BoolGetDatum(s->compression);
				values[4] = CStringGetTextDatum(s->version);
				values[5] = CStringGetTextDatum(s->cipher);
				values[6] = CStringGetTextDatum(s->client_dn);
			}
			else
			{
				nulls[2] = true;
				nulls[3] = true;
				nulls[4] = true;
				nulls[5] = true;
				nulls[6] = true;
			}

			tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);

			/* Next call, look at the next slot of course */
			ctxinfo->currslot++;

			SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
		}
		else
		{
			/*
			 * Nothing in this slot, but keep scanning until until we have
			 * covered all slots.
			 */
			ctxinfo->currslot++;
		}
	}

	SRF_RETURN_DONE(funcctx);
}




/*
 * Mostly from contrib/sslinfo, just with a different return type.
 */
static char *
X509_NAME_to_cstring(X509_NAME *name)
{
	BIO		   *membuf = BIO_new(BIO_s_mem());
	int			i,
				nid,
				count = X509_NAME_entry_count(name);
	X509_NAME_ENTRY *e;
	ASN1_STRING *v;
	const char *field_name;
	size_t		size;
	char		nullterm;
	char	   *sp;
	char	   *dp;
	char	   *result;

	(void) BIO_set_close(membuf, BIO_CLOSE);
	for (i = 0; i < count; i++)
	{
		e = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
		v = X509_NAME_ENTRY_get_data(e);
		field_name = OBJ_nid2sn(nid);
		if (!field_name)
			field_name = OBJ_nid2ln(nid);
		BIO_printf(membuf, "/%s=", field_name);
		ASN1_STRING_print_ex(membuf, v,
							 ((ASN1_STRFLGS_RFC2253 & ~ASN1_STRFLGS_ESC_MSB)
							  | ASN1_STRFLGS_UTF8_CONVERT));
	}

	/* ensure null termination of the BIO's content */
	nullterm = '\0';
	BIO_write(membuf, &nullterm, 1);
	size = BIO_get_mem_data(membuf, &sp);
	dp = pg_any_to_server(sp, size - 1, PG_UTF8);

	result = pstrdup(dp);
	if (dp != sp)
		pfree(dp);
	BIO_free(membuf);

	return result;
}
