#include "config_rss.h"

//Set default values TODO remove
struct lcore_params lcore_params[LCORE_PARAMS_MAX] = {
	{0, 0, 2},
	{0, 1, 3},
	{0, 2, 4},
	{1, 0, 5},
	{1, 1, 6},
	{1, 2, 7},
	{2, 0, 8},
	{3, 0, 9},
	{3, 1, 10},
	{4, 0, 11},
	{4, 1, 12},
};
uint16_t nb_lcore_params = 9;
