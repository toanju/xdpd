#include "config_rss.h"

//Set default values TODO remove
struct lcore_params lcore_params[LCORE_PARAMS_MAX] = {
	{0, 0,  2}, {0, 1,  3}, {0, 2,  4},
	{1, 0,  5}, {1, 1,  6}, {1, 2,  7},
	{2, 0,  8}, {2, 1,  9}, {2, 2, 10},
	{3, 0, 11}, {3, 1, 12}, {3, 2, 13},
	{4, 0, 14},
	{5, 0, 14},
	{6, 0, 14},
	{7, 0, 14},
};
uint16_t nb_lcore_params = 16;
