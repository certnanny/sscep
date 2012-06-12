#ifndef ENGINE_H
#define ENGINE_H

#include "sscep.h"

void scep_engine_init(ENGINE *e);
ENGINE *scep_engine_load_dynamic(ENGINE *e);
void sscep_engine_report_error(void);
#endif