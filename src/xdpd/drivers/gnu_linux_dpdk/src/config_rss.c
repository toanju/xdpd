#include "config_rss.h"

//Set default values TODO remove
struct lcore_params lcore_params[LCORE_PARAMS_MAX] = {
	{0, 0,  2}, {0, 1,  3}, {0, 2,  4}, { 0, 3, 5 },
	{1, 0,  5}, {1, 1,  6}, {1, 2,  8}, { 1, 3, 9 },
	{2, 0, 10}, {2, 1, 11}, {2, 2, 12}, { 2, 3, 13 },
	{3, 0, 14}, {3, 1, 15}, {3, 2, 16}, { 3, 3, 17 },
	{4, 0, 18},
	{5, 0, 18},
	{6, 0, 18},
	{7, 0, 18},
};
uint16_t nb_lcore_params = 20;
