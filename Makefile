MODULES = pg_sslstatus
EXTENSION = pg_sslstatus
DATA = pg_sslstatus--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
