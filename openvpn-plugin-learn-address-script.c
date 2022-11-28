/*
 * learn-address-script OpenVPN plugin
 * 
 * Runs an external script to help define firewall rules and other address-specific options
 * It doesn't block the main openvpn process.
 * 
 * Functions required to be a valid OpenVPN plugin:
 * openvpn_plugin_open_v3
 * openvpn_plugin_func_v3
 * openvpn_plugin_close_v1
 */

/* Required to use strdup */
#define __EXTENSIONS__

/********** Includes */
#include <stddef.h>
#include <errno.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/********** Constants */
/* For consistency in log messages */
#define PLUGIN_NAME "learn-address-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0

/* Where we store our own settings/state */
struct plugin_context 
{
        plugin_log_t plugin_log;
        char * script_path;
        char * downrate;
        char * uprate;
};

/* Handle a learn address */
static int deferred_handler(struct plugin_context *context, 
                const char *envp[],
                const char *argv[])
{
        plugin_log_t log = context->plugin_log;
        pid_t pid;

        log(PLOG_DEBUG, PLUGIN_NAME, 
                        "Deferred handler using script_path=%s", 
                        context->script_path);

        pid = fork();

        /* Parent - child failed to fork */
        if (pid < 0) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "pid failed < 0 check, got %d", pid);
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Parent - child forked successfully 
         *
         * Here we wait until that child completes before notifying OpenVPN of
         * our status.
         */
        if (pid > 0) {
                pid_t wait_rc;
                int wstatus;

                log(PLOG_DEBUG, PLUGIN_NAME, "child pid is %d", pid);
                
                /* Block until the child returns */
                wait_rc = waitpid(pid, &wstatus, 0);

                /* Values less than 0 indicate no child existed */
                if (wait_rc < 0) {
                        log(PLOG_ERR, PLUGIN_NAME,
                                        "wait failed for pid %d, waitpid got %d",
                                        pid, wait_rc);
                        return OPENVPN_PLUGIN_FUNC_ERROR;
                }

                /* WIFEXITED will be true if the child exited normally, any
                 * other return indicates an abnormal termination.
                 */
                if (WIFEXITED(wstatus)) {
                        log(PLOG_DEBUG, PLUGIN_NAME, 
                                        "child pid %d exited with status %d", 
                                        pid, WEXITSTATUS(wstatus));
                        return WEXITSTATUS(wstatus);
                }

                log(PLOG_ERR, PLUGIN_NAME,
                                "child pid %d terminated abnormally",
                                pid);
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }


        /* Child Control - Spin off our sucessor */
        pid = fork();

        /* Notify our parent that our child faild to fork */
        if (pid < 0) 
                exit(OPENVPN_PLUGIN_FUNC_ERROR);
        
        /* Let our parent know that our child is working appropriately */
        if (pid > 0)
                exit(OPENVPN_PLUGIN_FUNC_SUCCESS);

        /* Child Spawn - This process actually spawns the script */
        
        /* Daemonize */
        umask(0);
        setsid();

        /* Close open files and move to root */
        int chdir_rc = chdir("/");
        if (chdir_rc < 0)
                log(PLOG_DEBUG, PLUGIN_NAME,
                                "Error trying to change pwd to \'/\'");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        /* Prepare args. The script expects downrate and uprate as 
           first two args after the script name. 
         * Note that argv is null-terminated.
        */
        int argv_count = 0;
        for (; argv[argv_count]; argv_count++) ;

        char * argv_with_rates [argv_count + 3]; //downrate, uprate, and terminating NULL
        argv_with_rates[0] = strdup(argv[0]);
        argv_with_rates[1] = strdup(context->downrate);
        argv_with_rates[2] = strdup(context->uprate);
        for(int i = 1; i < argv_count; i++)
                argv_with_rates[i+2] = strdup(argv[i]);
        argv_with_rates[argv_count+2] = NULL;

        int execve_rc = execve(context->script_path, 
                        (char *const*)argv_with_rates, 
                        (char *const*)envp);
        if ( execve_rc == -1 ) {
                switch(errno) {
                        case E2BIG:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: E2BIG");
                                break;
                        case EACCES:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: EACCES");
                                break;
                        case EAGAIN:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: EAGAIN");
                                break;
                        case EFAULT:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: EFAULT");
                                break;
                        case EINTR:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: EINTR");
                                break;
                        case EINVAL:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: EINVAL");
                                break;
                        case ELOOP:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ELOOP");
                                break;
                        case ENAMETOOLONG:
                                log(PLOG_DEBUG, PLUGIN_NAME,
                                                "Error trying to exec: ENAMETOOLONG");
                                break;
                        case ENOENT:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ENOENT");
                                break;
                        case ENOEXEC:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ENOEXEC");
                                break;
                        case ENOLINK:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ENOLINK");
                                break;
                        case ENOMEM:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ENOMEM");
                                break;
                        case ENOTDIR:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ENOTDIR");
                                break;
                        case ETXTBSY:
                                log(PLOG_DEBUG, PLUGIN_NAME, 
                                                "Error trying to exec: ETXTBSY");
                                break;
                        default:
                                log(PLOG_ERR, PLUGIN_NAME, 
                                                "Error trying to exec: unknown, errno: %d", 
                                                errno);
                }
        }
        exit(EXIT_FAILURE);
}

/* We require OpenVPN Plugin API v3 */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1()
{
        return OPENVPN_PLUGIN_VERSION_MIN;
}

/* 
 * Handle plugin initialization
 *        arguments->argv[0] is path to shared lib
 *        arguments->argv[1] is expected to be path to script
 *        arguments->argv[2] is downrate
 *        arguments->argv[3] is uprate
 */
OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                struct openvpn_plugin_args_open_in const *arguments,
                struct openvpn_plugin_args_open_return *retptr)
{
        plugin_log_t log = arguments->callbacks->plugin_log;
        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

        struct plugin_context *context = NULL;

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Tell OpenVPN we want to handle these calls */
        retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS);
        
        /* Checking if the second argument was provided, that's where 
         * the script name is passed
        */
        if(!arguments->argv[1])
        {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: no script_path specified in config file");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        context = calloc(1, sizeof(struct plugin_context));
        if (context == NULL)
        {
                log(PLOG_ERR, PLUGIN_NAME, "PLUGIN: allocating memory for context failed");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        context->plugin_log = log;
        context->script_path = strdup(arguments->argv[1]);
        context->downrate = strdup(arguments->argv[2]);
        context->uprate = strdup(arguments->argv[3]);

        /* Pass state back to OpenVPN so we get handed it back later */
        retptr->handle = (void *) context;

        log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Called when we need to handle  OPENVPN_PLUGIN_LEARN_ADDRESS call */
OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                struct openvpn_plugin_args_func_in const *arguments,
                struct openvpn_plugin_args_func_return *retptr)
{
        (void)retptr; /* Squish -Wunused-parameter warning */
        struct plugin_context *context = 
                (struct plugin_context *) arguments->handle;
        plugin_log_t log = context->plugin_log;

        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_func_v3");
        
        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if(arguments->type == OPENVPN_PLUGIN_LEARN_ADDRESS) {
                log(PLOG_DEBUG, PLUGIN_NAME,
                                "Handling learn address with deferred script");
                return deferred_handler(context, arguments->envp, arguments->argv);
        } else
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
        struct plugin_context *context = (struct plugin_context *) handle;
        free(context);
}
