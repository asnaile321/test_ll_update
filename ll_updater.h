#ifndef __UPDATER_H__
#define __UPDATER_H__

#include <stdint.h>
#include <stdbool.h>

#define OTA_ERR -1
#define OTA_OK 0
#define OTA_FAIL -1

struct app_info;

typedef enum s_action_state { sa_NORUN = 0, sa_restart, sa_ready, sa_in_process, sa_completed, sa_err } sact_sta_t;

typedef enum s_stage { sa_RESTART = 0, sa_IDLE, sa_RUNNING } sact_stage_t;

typedef sact_sta_t (*action_f)(struct app_info *, void *data);

typedef struct OTA_event_handler {
    void (*OnUpdateStatusChanged)(enum s_action_state sts);
    void (*OnProgressChanged)(char *curr_dev, char *curr_slot, char *curr_partition_lbl, int total_progress);
    void (*OnErrStatus)(int err);
} OTA_event_handler_t;

typedef struct update_request {
	unsigned int type;
	unsigned int partition;
	char *version;
	char *fpath;
	char *pkgfile;
	struct target_img *prev, *next;
} update_request_t;

typedef struct {
	uint32_t is_last_install : 1;
	uint32_t dummy: 31;
} app_config_t;

struct target_device_config {
	int storage;
	char **partition_lbls;
	uint16_t partition_nums;
};

struct target_desc {
	char *platform;
	uint16_t nums_of_device_config;
	struct target_device_config *devices;
	uint32_t feature_option;
};

typedef struct app_info {

//	app_config_t config;

	struct target_device_config *target_dev;

	sact_stage_t stage;

	//struct action_ctx {
		sact_sta_t sta;
		unsigned int progress;
		unsigned int sub_step;
		unsigned int ts;
		unsigned int retry;

		bool is_installing; ///?
		bool is_last_install_session;

		update_request_t last_request;
		unsigned int err;

		unsigned int failed_cnt;

		update_request_t session_req;
	//} ctx;

	unsigned last_install_slot;

	void *internal; // provider the ota helper and support for ssig_t layer process(ssig_t layer is isolated, in related)

} app_info_t;

typedef struct app_impl {
		app_config_t config;
		// impl routines and inf which needs
		struct ota_routines {
			sact_sta_t (*do_update)(app_info_t *);
			sact_sta_t (*confirm_completed)(app_info_t *);
			int (*verify_package)(app_info_t *, char *);
			int (*cleanup)(app_info_t *);
		} handlers;

		struct OTA_event_handler *evt_cb;
		app_info_t info;
} app_impl_t;

#endif /*__UPDATER_H__*/
