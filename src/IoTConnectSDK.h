#ifndef IOTCONNECTSDK_H
#define IOTCONNECTSDK_H


#include <zephyr/kernel.h>
#include <cJSON.h>
#include <time.h>

#define HTTPS_PORT "443"
#define HTTPS_HOSTNAME "discovery.iotconnect.io"

#define CONFIG_MQTT_LIB_TLS

// Declare the sleepTime variable
extern unsigned long sleepTime;

#if defined CONFIG_MQTT_LIB_TLS
#define IOTCONNECT_SERVER_MQTT_PORT         8883
#else
#define IOTCONNECT_SERVER_MQTT_PORT         1883
#endif

#define IOTCONNECT_SERVER_HTTP_PORT         443
#define MAXLINE 4096
#define TLS_SEC_TAG 42

int MQTT_Init(void);
int tls_setup(int fd);
void GetAllTwins(void);
int subscribe(void);
int broker_init(void);
void Received_cmd(char *in_cmd);
void UpdateTwin(char *key, char *value);
int provision_certificates(void);
int GetTimeDiff(char newT[25], char oldT[25]);
int Save_Sync_Responce(char *sync_data);
int SendData(char *Attribute_json_Data);
int fds_init(struct mqtt_client *c);
void TwinUpdateCallback(char *payload);
void DeviceCallback(char *payload);
int client_init(struct mqtt_client *client);
char *get_base_url(char*Host, char *cpid, char *env);
char *Sync_call(char *cpid, char *uniqueid, char *base_url);
void SendAck(char *Ack_Data, int messageType);
typedef void (*IOTConnectCallback)(char *PayLoad);
void data_print(uint8_t *prefix, uint8_t *data, char *topic, size_t len);
void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt);
int data_publish(struct mqtt_client *c, char *topic, enum mqtt_qos qos, uint8_t *data, size_t len);
int IoTConnect_init(char *CpID, char *UniqueID, IOTConnectCallback CallBack, IOTConnectCallback TwinCallBack, char *Env);
int IoTConnect_connect();
int IoTConnect_abort();

void IoT_Connect_main(void);

char *Sensor_data(void);


char *Get_Time(void);



#endif /* IOTCONNECTSDK_H */
