#ifndef DNSR_CONFIG_H
#define DNSR_CONFIG_H

extern char * REMOTE_HOST; ///< Remote DNS server address
extern int LOG_MASK; ///< Log print level, a four-bit binary number where the lowest to highest bits represent DEBUG, INFO, ERROR, and FATAL
extern int CLIENT_PORT; ///< Local DNS client port
extern char * HOSTS_PATH; ///< Hosts file path
extern char * LOG_PATH; ///< Log file path

/**
 * @brief Parse command line arguments
 * @param argc Number of arguments
 * @param argv Array of argument strings
 */
void init_config(int argc, char * const * argv);

#endif //DNSR_CONFIG_H