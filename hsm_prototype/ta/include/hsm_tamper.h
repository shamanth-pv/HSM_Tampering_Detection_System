#ifndef HSM_TAMPER_H
#define HSM_TAMPER_H

#define CMD_VOLTAGE_ANOMALY    5
#define CMD_TEMP_ANOMALY       8
#define CMD_ENCLOSURE_BREACH   7
#define CMD_I2C_TAMPER  0x00000006  // Add alongside your existing CMD_ defines
/* Unique ID for the HSM Trusted Application */
#define TA_HSM_TAMPER_UUID \
	{ 0x12345678, 0xabcd, 0x1234, \
		{ 0xab, 0xcd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06} }

/* Command IDs */
#define CMD_HEARTBEAT       0  // Periodic signal from Normal World
#define CMD_ZEROIZE_KEYS    1  // Triggered manually or by auto-detection
#define CMD_GET_STATUS      2  // Check if system is in 'Tamper' mode
#define CMD_GET_LOG_COUNT   4 // NEW: Fetch total number of logs

#define CMD_RESET_TAMPER    3  // Administrative Reset — clears journal, re-arms keys


#endif /*HSM_TAMPER_H*/