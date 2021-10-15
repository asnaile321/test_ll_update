#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include "utlist.h"
#include "uthash.h"
#include "ll_updater.h"

#define LOG_DEBUG printf
#define LOG_INFO printf
#define LOG_ERR printf
#define LOG_WARN printf

#define BOLT_SYS(x, m, b...) do { if (x != 0) { err = -1; printf ("%s [%d] " m, __LINE__, ## b); break;} } while (0)
#define BOLT_IF(cond, e, fmt, x...) { \
        if ((cond)) { LOG_ERR (fmt, ## x); err = e; break; } \
} do {} while (0)

#define SetNextClkMs(tv, interval_ms) do {               \
    uint32_t sec = 0;                                     \
    uint64_t nsec, msec = interval_ms;                                        \
    if (interval_ms > 1000UL) {                           \
        sec = interval_ms / 1000UL;                       \
        msec = (uint64_t)(interval_ms % 1000);               \
    }                                                     \
    nsec = msec * 1000000ULL;          \
    clock_gettime(CLOCK_MONOTONIC, &tv);                  \
    tv.tv_sec += sec;                                     \
    if ((uint64_t) (tv.tv_nsec + nsec) > 1000000000ULL) { \
        tv.tv_sec += 1;                                   \
        tv.tv_nsec = (tv.tv_nsec + nsec - 1000000000ULL); \
    } else                                                \
        tv.tv_nsec += nsec;                               \
} while (0)

#define MAX_NAME_SIZE 32
#define MAX_FILE_PATH 256
#define APP_RUNNING_LOOP_INTERVAL 2 //2s
#define STR_EXP(_x) # _x

#define OTA_RESPONSE_APP(pFunc, ...) ({\
    if (!impl->handlers.pFunc) { LOG_ERR ("OTA response api:%s is null\n", STR_EXP(pFunc)); ret = OTA_FAIL; } \
      else { LOG_INFO ("OTA_API Responsed request %s\n", STR_EXP(pFunc)); ret = impl->handlers.pFunc(__VA_ARGS__); \
}; ret;})

/*
 * lib_ota
 */

typedef enum update_err_status {
	E_STS_OK = 0,

	E_STS_ArgsErr,
	E_STS_AuthErr,
	E_STS_SysErr, 
	E_STS_UnknownRequest,

	E_STS_SetDevSlotAttr,
	E_STS_GetDevSlotAttr,
	E_STS_BadDevSlotAttr,
	E_STS_ParsePackage,
	E_STS_VerifyPackage,

	E_STS_NotRoot,
	E_STS_UpdateHandlerIsInvalid,
	//E_STS_NoValidHandler,
	//E_STS_CmdExecution,

	E_STS_ProgramTarget,
	E_STS_OutOfProgramRetryCnt,
	E_STS_ProgramTimeout,
	E_STS_ProgramUnexpected,
	E_STS_ProgramCompleted,
	E_STS_ProgramTargetFailed,
	E_STS_ProgramTargetTimeout,

	E_STS_SyncABSlots,
	E_STS_SyncABSlotsCompleted,

	E_STS_RemovePackage,
	E_STS_ClearTmpFile,

} sts_type_t;

typedef struct s_action_evt {
	const char type[32];
	void *data;
	action_f f;
	UT_hash_handle hh;
} s_action_evt_t;

typedef struct target_img { // image which for target partion updating
    char lbl[MAX_NAME_SIZE];
    char *fpath;
    UT_hash_handle hh;
} target_img_t;

typedef struct target_info {
	unsigned int dev;
	target_img_t imgs;
} target_info_t;

typedef struct sts {
	sts_type_t type;
	uint64_t when;
	struct sts *prev, *next;
} sts_t;

typedef struct ota_internal {

	target_info_t target;
	pthread_t thread;
	pthread_cond_t cond;
	pthread_condattr_t condattr;
	pthread_mutex_t lock;
	sts_t *queue;
	unsigned int run;

	s_action_evt_t sta_handlers; // ota app events
	app_impl_t *ota_impl;

	sem_t req_notify;
} ota_internal_t;

ota_internal_t g9x_internal;

app_impl_t *ota_impl = NULL;

int sts_populate(sts_type_t type)
{
	ota_internal_t *oi = &g9x_internal;
	sts_t *sig = NULL;
	int err = 0;
	do {
		pthread_mutex_lock(&oi->lock);
		BOLT_IF ((sig = (sts_t *)malloc(sizeof(sts_t))) != 0, "", OTA_ERR, "ssig malloc .. failed\n");
		BOLT_IF (!type, "", OTA_ERR, "ssig reigst is .. failed\n");
		sig->type = type;
		DL_APPEND(oi->queue, sig);
		pthread_cond_signal(&oi->cond);
		pthread_mutex_unlock(&oi->lock);
	} while (0);

	return err;
}

sts_t * wait_sts_pending(unsigned int wait_ms)
{
	int err = 0;
	struct timespec tv;
	ota_internal_t *oi = &g9x_internal;
	sts_t *s = NULL;

	while (oi->run) {
		if (pthread_mutex_lock(&oi->lock)) {
			LOG_INFO("lock failed\n");
			continue;
		}

		int rc = 0;
		SetNextClkMs(tv, wait_ms);
		LOG_INFO ("----next %d %ll--\n", (uint64_t)tv.tv_sec, (uint64_t)tv.tv_nsec);

		// you need to get lock to check, but cond always get lock now ???
		while (oi->run && !(s = oi->queue) && rc != ETIMEDOUT) {
			rc = pthread_cond_timedwait(&oi->cond, &oi->lock, &tv);

			if (rc != EINTR && rc != ETIMEDOUT) {
				LOG_ERR ("pthread wait fault: %s\n", strerror(rc));
				pthread_mutex_unlock(&oi->lock);
				return NULL;
			}
		}

		uint64_t curr = ((uint64_t)tv.tv_sec) * 1000ULL + \
				tv.tv_nsec / 1000000ULL;

		while (s) {
			DL_DELETE(oi->queue, s);
			pthread_mutex_unlock(&oi->lock);

			LOG_INFO("get sts signal triggered \n");
			s->when = curr;

			// filter and decide the sts
			goto GET_STS_SIGNAL;
		}
		pthread_mutex_unlock(&oi->lock);
	}

GET_STS_SIGNAL:
    return s;
}

update_request_t * get_request()
{   // get user inputs
	if (!ota_impl) {
		LOG_ERR ("ota impl is not valid...fault\n");
		return NULL;
	}
	ota_internal_t *oi = (ota_impl->info).internal;
    if (oi) {
        int rc = sem_wait(&oi->req_notify);
        if (!rc) {
            LOG_ERR ("got user ota request\n");
        } else
            LOG_ERR ("get user ota request is ...failed, %s\n",strerror(rc));
    }
    return NULL;
}

static int request_id(const char *pkgfile)
{
    // TODO
    return 0;
}

static int64_t currentms()
{
	//TODO
	return 0;
}

int ota_do_install(app_info_t *info, update_request_t *req)
{
	struct timespec loopDelay = {APP_RUNNING_LOOP_INTERVAL, 0};
	unsigned int new_request_id = 0;
	sts_type_t install_result = 0, ret;

	app_info_t * c = info;
	app_impl_t * impl = ((ota_internal_t *)info->internal)->ota_impl;

Retry:
	new_request_id = request_id(req->pkgfile);
	//c->sub_step = req->type;
	c->sub_step = 0;
	//c->current_version();
	c->ts = currentms();

	do {
		if (!c->is_installing) {
			// verify package and get the payload file, if not do it
			if (impl->handlers.verify_package(c, req->pkgfile) != 0) {
				LOG_ERR("ua_install: prepared package is invalid!\n");
				install_result = E_STS_VerifyPackage;
				break;
			}
			//start update session
			c->progress = 0;
			c->sub_step = 1;
			c->is_installing = true;

		} else {
			// check the last campaign is report or not,
			// but maybe there has a confusion record file exist, (maybe we should query updates from dmclient)
			if (c->is_last_install_session) {
				c->is_last_install_session = false;
				c->is_installing = false;

				//if (request_id(c->last_session_req.type, c->last_session_req.pkgName, c->last_session_req.version) == new_request_id) {
				if (request_id(req->pkgfile) == new_request_id) {
					LOG_WARN("re-install request, \n");
				} else {
					LOG_WARN("a new install session be accepted, remove the confusion old record file \n");
					impl->handlers.cleanup(c);
					c->failed_cnt = 0;
					continue;
				}
			}
		}

		switch (c->sub_step) {
			case 0:default: install_result = OTA_RESPONSE_APP(confirm_completed, info); break;
			case 1: c->sub_step = 0; install_result = OTA_RESPONSE_APP(do_update, info); break;
			//case 2: c->sub_step = 0; install_result = OTA_RESPONSE_APP(DoSyncABSlots, info); break;
		}
		nanosleep(&loopDelay, NULL);
	} while ((install_result == E_STS_ProgramTarget ||
		install_result == E_STS_SyncABSlots)&& c->sub_step <= 1);

	if (install_result == E_STS_OutOfProgramRetryCnt || install_result == E_STS_ProgramTimeout ||
			install_result == E_STS_ProgramUnexpected || install_result == E_STS_ProgramCompleted ||
			install_result == E_STS_ProgramTargetFailed || install_result == E_STS_SyncABSlotsCompleted) {

		c->is_installing = false;
		c->is_last_install_session = false;
		impl->handlers.cleanup(c);

		if (install_result == E_STS_ProgramTargetFailed && c->retry) {
			c->retry --;
			LOG_INFO("Re-do install again [retry times:%d]",c->retry);
			install_result = E_STS_ProgramTarget;
			goto Retry;
		}
		c->failed_cnt = 0;

		if (install_result == E_STS_ProgramCompleted || install_result == E_STS_SyncABSlotsCompleted) {
			//??ret = ua_backup_package((char *)c->session_req.type, (char *)c->session_req.pkgName, (char *)c->session_req.version);
			//??LOG_INFO ("%s%s\n", ((ret == OTA_OK) ? "Success backup the package" : "Fail to backup the package"), c->session_req.pkgfile);
			//??LOG_INFO ("%s%s\n", ((ret == OTA_OK) ? "Success backup the package" : "Fail to backup the package"), req->pkgfile);
		}

		//remove the installed target package folder
		//??snprintf(target_pkg_dir, MAX_FILE_PATH, "%s.dir", req->pkgFile);
		//??(void)rm_pkgFile_dir(target_pkg_dir);
	}

	return 0;
}

void* runner_loop(void *arg)
{
	app_impl_t *impl = (app_impl_t *)arg;
	app_info_t *c = &impl->info;
	ota_internal_t *oi = c->internal;
	int rc;

	while (oi->run) {
		rc = sem_wait(&oi->req_notify);
		if (rc) {
			LOG_INFO ("Wait request is .. error %s\n", strerror(rc));
			continue;
		}

		(void)ota_do_install(c, &c->session_req);
	}

	return 0;
}

#define resp() ((ota_internal_t)info->internal)

void otaOnUpdateStatusChanged(enum s_action_state sts) {
	//TODO
}
void otaOnProgressChanged(char *curr_dev, char *curr_slot, char *curr_partition_lbl, int total_progress) {
	//TODO
}
void otaOnErrStatus(int err) {
	//TODO
}

/* app
*/

int register_ota_event(app_impl_t *impl)
{
	struct OTA_event_handler h = {
		.OnUpdateStatusChanged = otaOnUpdateStatusChanged,
		.OnProgressChanged = otaOnProgressChanged,
		.OnErrStatus = otaOnErrStatus,
	};

    if (!impl) {
        LOG_ERR("Register ota application callback ..failed (ota_impl is null)\n");
        return OTA_ERR;
    }
    impl->evt_cb = &h;
    LOG_INFO("Register ota application callback functions\n");
    return OTA_OK;
}

int register_app(app_impl_t *impl)
{
	if (ota_impl) {
		LOG_WARN ("Warning the ota_impl is not empty\n");
	}
	ota_impl = impl;
	if (!ota_impl) {
		LOG_ERR ("Err: null app impl wrong\n");
		return -1;
	}

	if (register_ota_event(impl)) {
		LOG_ERR ("Err: register ota event is wrong\n");
		return -1;
	}

	int err = OTA_OK;
	(impl->info).internal = &g9x_internal;
	ota_internal_t *oi = (ota_internal_t *)((impl->info).internal);
	do {
		oi->run = 1;
		BOLT_IF (pthread_mutex_init(&oi->lock, 0), "", OTA_ERR, "pthread mutex init .. failed");
		BOLT_IF (pthread_cond_init(&oi->cond, 0), "", OTA_ERR, "pthread cond init .. failed");
		BOLT_IF (pthread_create(&oi->thread, 0, runner_loop, ota_impl), "", OTA_ERR, "pthread create .. failed");
	} while (0);

	return err;
}

int unregister_app(app_impl_t *impl)
{
	//join();
}

//??sact_sta_t g9x_do_update(app_info_t * info, update_request_t *req){
sact_sta_t g9x_do_update(app_info_t * info){
	return 0;
}

//??sact_sta_t g9x_confirm_completed(app_info_t *info, int is_last_install){
sact_sta_t g9x_confirm_completed(app_info_t *info){
	return 0;
}

int g9x_verify_package(app_info_t *info, char * pkgfile){
	return 0;
}

int g9x_cleanup(app_info_t *info){
	return 0;
}

int CheckSlotAttrReady(app_info_t *info){
	return 0;
}

static void ota_close(){
}

static bool is_need_ab_slot(){
	return false;
}

//TODO, request unit
int DoUpdate(app_info_t *info, update_request_t *req)
{
	ota_internal_t *oi = (ota_internal_t *)(info->internal);
	unsigned int is_valid = oi->run;
	if (!is_valid) {
		LOG_WARN ("resp is not valid for process request (status:%d)\n", is_valid);
		return E_STS_UpdateHandlerIsInvalid;
	}

	memset(&info->session_req, 0, sizeof(update_request_t));
	// lock (req) TODO
	//f_malloc (req) TODO
	memcpy(&info->session_req, req, sizeof(update_request_t));
	//oi->req_notify = 1;
	int rc = sem_post(&oi->req_notify);
	if (rc) {
		LOG_ERR ("User action signal send .. failed (%s)\n", strerror(rc));
		return E_STS_UpdateHandlerIsInvalid;
	}

	LOG_INFO ("OTA updating ...\n");
	return rc;
}

enum devdef {
	DEV_EMMC0 = 0,
	DEV_SPI_NOR0
};

const char target_lbls[][MAX_NAME_SIZE] = {
    // partitions for DEV_EMMC0 
    "bootloader",
    //"atf",
    //"tos",
    //"vbmeta",
    "rootfs",
    "dtb",
    //"dtbo",
    "kernel",
    "userdata",
    // partitions for mtd(ospi) DEV_SPI_NOR0
    //"dil",
    //"dil_bak",
    "dil2",
    "ddr_init_seq",
    "ddr_fw",
    "sdpe_fw",
    "routing-table",
    //"system_config",
    "ssystem",
    "hsm_fw",
    "preloader",
    //"vbmeta",
    "safety_os",
    //"misc",
};

static struct target_device_config dev_cfgs[2] = {
    [0] = {
        .storage = DEV_EMMC0,
        .partition_lbls = (char **)target_lbls[0],
        .partition_nums = 5,
    },
    [1] = {
        .storage = DEV_SPI_NOR0,
        .partition_lbls = (char **)target_lbls[5],
        .partition_nums = 9,
    },
};

static struct app_impl g9x_impl = {
    .config = {
		.is_last_install = 0,
	},
    .handlers = {
        .do_update = g9x_do_update,
        .confirm_completed = g9x_confirm_completed,
        .verify_package = g9x_verify_package,
        .cleanup = g9x_cleanup,
    },
    .evt_cb = NULL,
};

app_impl_t *ota_impl_init()
{
	return &g9x_impl;
}

int main(int argc, char *argv[])
{
	//cfg = argv;

	if (register_app(ota_impl_init())) {
		LOG_ERR ("ERROR: register ota app is failed\n");
		exit(1);
	}

	app_info_t *c = &ota_impl->info;
	update_request_t *req = NULL;
	sts_t * sts;
	int res;
	int wait_ms = 50;
	while (1) {
		//scheduler processes 
		if (c->sta <= sa_restart) {
			res = CheckSlotAttrReady(c);
			if (res) {
				LOG_ERR("err:%d,Check slots attrbution is .. failed\n", res);
			}
		} else if (c->sta == sa_ready) {
			if (!c->is_last_install_session)
				req = get_request();
			else
				req = &c->last_request;

			if (req) {
				//res = OTA_RESPONSE_APP(DoUpdate, info, req);
				res = DoUpdate(c, req);
				if (res) {
					LOG_ERR("err:%d,request update is .. failed\n", res);
					continue;
				}
			}
		} else { // sa_RUNNING
			if (c->sta == sa_completed || c->sta == sa_err) {
				ota_close();
				c->sta = sa_ready;
			} else { // in progress
				//send_hmi_progress_info();
			}
		}

wait_sts:
		sts = wait_sts_pending(wait_ms);
		if (!sts) {
			usleep(10000);
			LOG_DEBUG ("Debug: user got session (%d) status is.. NULL\n", req->type);
			//goto wait_sts;
			continue;
		}
		switch (sts->type) {
			case E_STS_GetDevSlotAttr:
				if (is_need_ab_slot(sts))
					c->sta = sa_restart;
				else {
					//set_ab_success
					c->sta = sa_ready;
				}
				//c->stage = sa_IDLE;
				wait_ms = -1;
			break;
			case E_STS_ProgramTargetFailed:
			case E_STS_ProgramTargetTimeout:
			case E_STS_ProgramUnexpected:
				if (c->sta >= sa_ready) {
					c->sta = sa_err;
				}
			break;
			case E_STS_ProgramCompleted:
				if (c->sta >= sa_ready) {
					c->sta = sa_completed;
				}
			break;
			case E_STS_ProgramTarget:
			case E_STS_OutOfProgramRetryCnt:
				if (c->sta >= sa_ready) {
					c->sta = sa_in_process;
				}
			break;

			case E_STS_RemovePackage:
			case E_STS_ClearTmpFile:
			break;
		}
	}
	return 0;
}
