


#include <string.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <zephyr/net/socket.h>
//#include <zephyr/net/bsdlib.h>
#include <zephyr/net/tls_credentials.h>
#include <cJSON.h>
#include <modem/lte_lc.h>
#include <modem/pdn.h>

#include <date_time.h>
//#include <at_cmd.h>
//#include <modem/at_notif.h>
#include <modem/modem_key_mgmt.h>
#include <zephyr/net/mqtt.h>
#include "IoTConnectSDK.h"
 #include "IoTConnect_Config.h" 
#include "../IoTConnect/cert/certificates.h"
#include <sensor/hx711/hx711.h>
LOG_MODULE_REGISTER(Logs2); 

// Declare the measure_weight function
 //void measure_weight(void);

//char *Attribute_json_Data = " ";
char *Sensor_data(void);
char *Get_Time(void);

//extern int battery_percentage;
extern int16_t weight_grams; 
extern char battery_data_str[];  
//extern float truncatedNumber;
//extern int battery_percentage;
//void calibrate_sensor(void); /* Function for Calibrating sensors*/
//void measure_weight(void);   /*Function for measuring weight*/

int provision_certificates(void);

static struct sockaddr_storage broker;
static bool connected;
static bool pubAck;
 bool GSM_MODEM_FLAG = true;
//static bool pubStart;
static struct pollfd fds;
struct Sync_Resp SYNC_resp;

#define CONFIG_PROVISION_CERTIFICATES

//#define CONFIG_MQTT_LIB_TLS

/* Certificate for `example.com` */
static const char cert[] = {
//#include "../cert/DigiCertGlobalRootCA_g2.pem"
#include "../cert/rootCA.pem"
};

BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");

/* Buffers for MQTT client. */
static uint8_t rx_buffer[MAXLINE];
static uint8_t tx_buffer[MAXLINE];
static uint8_t payload_buf[MAXLINE];
//BUILD_ASSERT_MSG(sizeof(CLOUD_CA_CERTIFICATE) < KB(4), "Certificate too large");

typedef struct Sync_Resp{
    char *cpId;
    const char *dtg;      //root..info
    int ee;
    int rc;
    int at;
    int ds;
    int df;
    struct protocol{
          char *name;
          char *host;
          char *Client_Id;    //data..protocol
          char *user_name;
          char *pass;
          char *pub_Topic;
          char *sub_Topic;
        } Broker;
    
};

/* Provision certificate to modem */
int cert_provision(void)
{
	int err;
	bool exists;
	int mismatch;

	/* It may be sufficient for you application to check whether the correct
	 * certificate is provisioned with a given tag directly using modem_key_mgmt_cmp().
	 * Here, for the sake of the completeness, we check that a certificate exists
	 * before comparing it with what we expect it to be.
	 */
	err = modem_key_mgmt_exists(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, &exists);
	if (err) {
		LOG_ERR("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		mismatch = modem_key_mgmt_cmp(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, cert,
					      strlen(cert));
		if (!mismatch) {
			LOG_INF("Certificate match\n");
			return 0;
		}

		LOG_ERR("Certificate mismatch\n");
		err = modem_key_mgmt_delete(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			LOG_ERR("Failed to delete existing certificate, err %d\n", err);
		}
	}

	LOG_INF("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, cert,
				   sizeof(cert) - 1);
	if (err) {
		LOG_ERR("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup_m(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

#if defined(CONFIG_SAMPLE_TFM_MBEDTLS)
	err = tls_credential_add(tls_sec_tag[0], TLS_CREDENTIAL_CA_CERTIFICATE, cert, sizeof(cert));
	if (err) {
		return err;
	}
#endif

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		LOG_ERR("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag, sizeof(tls_sec_tag));
	if (err) {
		LOG_ERR("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, HTTPS_HOSTNAME, sizeof(HTTPS_HOSTNAME) - 1);
	if (err) {
		LOG_ERR("Failed to setup TLS hostname, err %d\n", errno);
		return err;
	}
	return 0;
}

char recv_buf[MAXLINE];
char send_buf[2047 + 1];
char *CPID =NULL, *Burl =NULL;
char *ENVT =NULL, *UNIQUEID =NULL;
//char *Dpayload = " ", *Tpayload =NULL;
        bool Flag_99 = true;
        bool Isdebug = true;
        char LastTime[25] = "0000-00-00T00:00:00.000Z";
        //char *Discovery = "discovery.iotconnect.io";
        const char *httpAPIVersion = "2016-02-03";
        
        char* const  twinPropertyPubTopic ="$iothub/twin/PATCH/properties/reported/?$rid=1";
        char* const  twinPropertySubTopic ="$iothub/twin/PATCH/properties/desired/#";
        char* const  twinResponsePubTopic ="$iothub/twin/GET/?$rid=0";
        char* const  twinResponseSubTopic ="$iothub/twin/res/#";



#if defined(CONFIG_PROVISION_CERTIFICATES)

#if 0
#define MAX_OF_2 MAX(sizeof(CLOUD_CA_CERTIFICATE),\
		     sizeof(CLOUD_CLIENT_PRIVATE_KEY))
#define MAX_LEN MAX(MAX_OF_2, sizeof(CLOUD_CLIENT_PUBLIC_CERTIFICATE))
static uint8_t certificates[][MAX_LEN] = {{CLOUD_CA_CERTIFICATE},
				       {CLOUD_CLIENT_PRIVATE_KEY},
				       {CLOUD_CLIENT_PUBLIC_CERTIFICATE} };
static const size_t cert_len[] = {
	sizeof(CLOUD_CA_CERTIFICATE) - 1, sizeof(CLOUD_CLIENT_PRIVATE_KEY) - 1,
	sizeof(CLOUD_CLIENT_PUBLIC_CERTIFICATE) - 1
};

int provision_certificates(void)
{
	int err;

        nrf_sec_tag_t sec_tag = 1; //CONFIG_CLOUD_CERT_SEC_TAG;
        /*
	    enum modem_key_mgnt_cred_type cred[] = 
        */
        uint8_t type;
        uint8_t cred[] = 
        {
		    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
		    MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
		    MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT,
	    };

	/* Delete certificates */
	for (type = 0; type < 3; type++) {
		err = modem_key_mgmt_delete(sec_tag, (enum modem_key_mgmt_cred_type)cred[type]);
		printk("modem_key_mgmt_delete(%u, %d) => result=%d\n",
				sec_tag, type, err);
	}

	/* Write certificates */
	for (type = 0; type < 3; type++) {
		err = modem_key_mgmt_write(sec_tag, (enum modem_key_mgmt_cred_type)cred[type],
				certificates[type], cert_len[type]);
		printk("modem_key_mgmt_write => result=%d\n", err);
	}
	return 0;
}
#else
#define TLS_SEC_TAG_IOTCONNECT_MQTT     10701
int nrf_cert_store_save_device_cert(void) 
{
    int err = 0;

    const char *certificates[] = {CLOUD_CA_CERTIFICATE,
                                  CLOUD_CLIENT_PRIVATE_KEY,
                                  CLOUD_CLIENT_PUBLIC_CERTIFICATE
    };
    //nrf_sec_tag_t sec_tag = TLS_SEC_TAG_IOTCONNECT_MQTT; //CONFIG_CLOUD_CERT_SEC_TAG;
    enum modem_key_mgmt_cred_type credentials[] = {
            MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
            MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
            MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT,
    };

    /* Delete certificates up to 5 certs from the modem storage for our sec key
     * in case there are any other remaining */
    for (int index = 0; index < 5; index++) {
        (void) modem_key_mgmt_delete(TLS_SEC_TAG_IOTCONNECT_MQTT, index);
        
        LOG_INF("modem_key_mgmt_delete(%d, %d) => result=%d\n",
               TLS_SEC_TAG_IOTCONNECT_MQTT, index, err);
    }

    /* Write certificates */
    for (enum modem_key_mgmt_cred_type type = 0; type < ARRAY_SIZE(credentials); type++) {
        err |= modem_key_mgmt_write(TLS_SEC_TAG_IOTCONNECT_MQTT, credentials[type],
                                    certificates[type], strlen(certificates[type]));
        LOG_INF("modem_key_mgmt_write => result=%d\n", err);
    }
    return err;
}
#endif

#endif

#if 1
// this function will get the UTC time 
char Date[25] = "20   ";
static char timebuf[sizeof "2011-10-08T07:07:01.000Z"];
int64_t current_time_ms;

char *Get_Time(void)
{
	struct timespec tp = { 0 };
	struct tm ltm = { 0 };
	int err;
    //return to_iso_timestamp(NULL);
    //printk("Get time ...\n");
    err = date_time_now(&current_time_ms);

    //err = date_time_ntp_get(&current_time_ms);
    tp.tv_sec = current_time_ms / 1000;
    localtime_r(&tp.tv_sec, &ltm);
	snprintf(Date, 25, "%04u-%02u-%02uT%02u:%02u:%02u.000Z",
		ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,
		ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
    return Date;

    //strftime(timebuf, (sizeof timebuf), "%Y-%m-%dT%H:%M:%S.000Z", current_time);
} 
#endif


uint16_t mid_num = 0;

/**@brief Function to publish data on the configured topic
 */
int data_publish(struct mqtt_client *c, char *topic, enum mqtt_qos qos,
	uint8_t *data, size_t len)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = topic;
	param.message.topic.topic.size = strlen(param.message.topic.topic.utf8);
	param.message.payload.data = data;
	param.message.payload.len = len;
	param.message_id = ++mid_num;       //sys_rand32_get();
	param.dup_flag = 0;
	param.retain_flag = 0;

	return mqtt_publish(c, &param);
}

static struct mqtt_client client;
/**@brief Function to subscribe to the configured topic
 */
int subscribe(void)
{
	struct mqtt_topic subscribe_topic[2] = 
    {
		{.topic = 
            {
			    .utf8 = SYNC_resp.Broker.sub_Topic,
			    .size = strlen(SYNC_resp.Broker.sub_Topic)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        },

        {.topic = 
            {
			    .utf8 = SYNC_resp.Broker.pub_Topic,
			    .size = strlen(SYNC_resp.Broker.pub_Topic)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        },
        //#if 1
        {.topic = 
            {
			    .utf8 = twinResponseSubTopic,
			    .size = strlen(twinResponseSubTopic)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        }
        //#endif
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = ARRAY_SIZE(subscribe_topic),
		.message_id = 5678
	};


	return mqtt_subscribe(&client, &subscription_list);
}

/**@brief Function to read the published payload.
 */
int publish_get_payload(struct mqtt_client *c, size_t length)
{
	uint8_t *buf = payload_buf;
	uint8_t *end = buf + length;

	if (length > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}

	while (buf < end) {
		int ret = mqtt_read_publish_payload(c, buf, end - buf);

		if (ret < 0) {
			int err;

			if (ret != -EAGAIN) {
				return ret;
			}

			printk("mqtt_read_publish_payload: EAGAIN\n");

			err = poll(&fds, 1, CONFIG_MQTT_KEEPALIVE);         //K_SECONDS(CONFIG_MQTT_KEEPALIVE));
			if (err > 0 && (fds.revents & POLLIN) == POLLIN) {
				continue;
			} else {
				return -EIO;
			}
		}

		if (ret == 0) {
			return -EIO;
		}

		buf += ret;
	}

	return 0;
}

/**@brief MQTT client event handler
 */
void mqtt_evt_handler(struct mqtt_client *const c,
		      const struct mqtt_evt *evt)
{
	int err;
	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			//printk("MQTT connect failed %d\n", evt->result);
			break;
		}

		//printk("[%s:%d] MQTT client connected!\n", __func__, __LINE__);
                subscribe();
                cJSON *obj;
                obj = cJSON_CreateObject();
                cJSON_AddStringToObject(obj, "cpid",CPID);
                cJSON_AddStringToObject(obj, "uniqueId",UNIQUEID);
                cJSON_AddStringToObject(obj, "guid","");
                cJSON_AddBoolToObject(obj, "ack",false);
                cJSON_AddStringToObject(obj, "ackId","");
                cJSON_AddBoolToObject(obj, "command", true);
                cJSON_AddStringToObject(obj, "cmdType","0x16");
                (*DeviceCallback)(cJSON_Print(obj));
                //if(Isdebug)
                    //printk("\r\n\tINFO_IN02 [%s-%s] : Device connected\n",CPID,UNIQUEID);
		
		break;

	case MQTT_EVT_DISCONNECT:
		//printk("MQTT client disconnected %d\n", evt->result);
                cJSON *obj2;
                obj2 = cJSON_CreateObject();
                cJSON_AddStringToObject(obj2, "cpid",CPID);
                cJSON_AddStringToObject(obj2, "uniqueId",UNIQUEID);
                cJSON_AddStringToObject(obj2, "guid","");
                cJSON_AddBoolToObject(obj2, "ack",false);
                cJSON_AddStringToObject(obj2, "ackId","");
                cJSON_AddBoolToObject(obj2, "command", false);
                cJSON_AddStringToObject(obj2, "cmdType","0x16");
                (*DeviceCallback)(cJSON_Print(obj2));
                //if(Isdebug)
                    //printk("\r\n\tINFO_IN03 [%s-%s] : Device Disconnected\n",CPID,UNIQUEID);
		        connected = false;
		break;

	case MQTT_EVT_PUBLISH: 
    {
		const struct mqtt_publish_param *p = &evt->param.publish;
                
		//printk("MQTT PUBLISH DONE pk %d result=%d len=%d\n", p->message_id, evt->result, p->message.payload.len);
		err = publish_get_payload(c, p->message.payload.len);
		if (err >= 0) 
        {
			data_print("Received: ", payload_buf, p->message.topic.topic.utf8, p->message.payload.len);
		} 
        else 
        {
			printk("mqtt_read_publish_payload: Failed! %d\n", err);
			printk("Disconnecting MQTT client...\n");

			err = mqtt_disconnect(c);
			if (err) 
            {
				printk("Could not disconnect: %d\n", err);
			}
		}
	} break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) 
        {
			printk("MQTT PUBACK error %d\n", evt->result);
		}
        else
        {
		    printk("PUBACK packet id: %u\n", evt->param.puback.message_id);
            pubAck = true;
         /*
            err = mqtt_disconnect(c);
         if (err) 
            {
			printk("Could not disconnect: %d\n", err);
		    }
        */
        }
		break;

	case MQTT_EVT_SUBACK:
		if (evt->result != 0) 
        {
			printk("MQTT SUBACK error %d\n", evt->result);
			break;
		}

		printk("SUBACK packet id: %u\n", evt->param.suback.message_id);
        connected = true;
		break;

    case MQTT_EVT_PINGRESP:
        printk("PING alive ACK %d\n", evt->type);
        break;

	default:
		printk("MQTT event type %d\n", evt->type);
		break;
	}
}

int broker_init(void)
{
	int err;
    int retry = 10;
	struct addrinfo *result;
	struct addrinfo *addr;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};

    while (retry>0)
    {   
        k_msleep(50);
	    err = getaddrinfo(SYNC_resp.Broker.host, NULL, &hints, &result);
        if (err == 0)
            retry=0;
        else
            retry--;
    }
	
	if (err) 
    {
		printk("ERROR: BROKER getaddrinfo failed %d\n", err);
        return err;
	}

	addr = result;
	err = -ENOENT;
	
	while (addr != NULL) {
		if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *broker4 =
				((struct sockaddr_in *)&broker);
			char ipv4_addr[NET_IPV4_ADDR_LEN];

			broker4->sin_addr.s_addr =
				((struct sockaddr_in *)addr->ai_addr)
				->sin_addr.s_addr;
			broker4->sin_family = AF_INET;
			broker4->sin_port = htons(IOTCONNECT_SERVER_MQTT_PORT);

			inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
				  ipv4_addr, sizeof(ipv4_addr));
			printk("\nMQTT Broker IPv4 Address found %s\n", ipv4_addr);

			break;
		} else {
			printk("ai_addrlen = %u should be %u or %u\n",
				(unsigned int)addr->ai_addrlen,
				(unsigned int)sizeof(struct sockaddr_in),
				(unsigned int)sizeof(struct sockaddr_in6));
		}

		addr = addr->ai_next;
		break;
	}
	freeaddrinfo(result);
    return 0;
}

#if 1 //was_mod
struct mqtt_utf8 mqtt_user_name;
struct mqtt_utf8 mqtt_pass;
#endif


#if defined(CONFIG_PROVISION_CERTIFICATES)
static sec_tag_t sec_tag_list[] = { TLS_SEC_TAG_IOTCONNECT_MQTT };

static void nrf_cert_store_configure_tls(struct mqtt_sec_config *tls_config)
{
    tls_config->sec_tag_count = ARRAY_SIZE(sec_tag_list);
    tls_config->sec_tag_list = sec_tag_list;
}
#endif

#define MQTT_TOKEN

int client_init(struct mqtt_client *client)
{
    int err;
	mqtt_client_init(client);
    client->keepalive = 240;
    k_msleep(2000);
	err = broker_init();
    if (err != 0)
    {
        return -1;
    }
	
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
#if 1 //wads_mod
        
        client->client_id.utf8 = SYNC_resp.Broker.Client_Id;
        client->client_id.size = strlen(client->client_id.utf8);
        
        mqtt_user_name.utf8 = SYNC_resp.Broker.user_name;
        mqtt_user_name.size = strlen(mqtt_user_name.utf8);

        mqtt_pass.utf8 = SYNC_resp.Broker.pass;
        mqtt_pass.size = strlen(mqtt_pass.utf8);
        
        #if defined(MQTT_TOKEN)  
        client->user_name = &mqtt_user_name;
        client->password = &mqtt_pass;
        #else
        client->user_name = &mqtt_user_name;
        client->password = NULL; 
        #endif
#else
	client->client_id.utf8 = (u8_t *)CONFIG_MQTT_CLIENT_ID;
	client->client_id.size = strlen(CONFIG_MQTT_CLIENT_ID);
	client->password = NULL;
	client->user_name = NULL;
#endif //wads_mod
	client->protocol_version = MQTT_VERSION_3_1_1;

	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);
	
#if defined(CONFIG_MQTT_LIB_TLS)
	struct mqtt_sec_config *tls_config = &client->transport.tls.config;

	client->transport.type = MQTT_TRANSPORT_SECURE;
#if 1 //wads_mod
	tls_config->peer_verify = 1;
#else
	tls_config->peer_verify = 2;
#endif  
	tls_config->cipher_count = 0;
	tls_config->cipher_list = NULL;
    #if defined(MQTT_TOKEN)  
    #else
    nrf_cert_store_configure_tls(tls_config);
    #endif
    tls_config->hostname = SYNC_resp.Broker.host;
        
#else
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif
    return 0;
}

int fds_init(struct mqtt_client *c)
{
	if (c->transport.type == MQTT_TRANSPORT_NON_SECURE) {
		fds.fd = c->transport.tcp.sock;
	} else {
#if defined(CONFIG_MQTT_LIB_TLS)
		fds.fd = c->transport.tls.sock;
#else
		return -ENOTSUP;
#endif
	}

	fds.events = POLLIN;

	return 0;
}

///////////////////////////////////////////////////////////////////////////////////
// MQTT will work in while loop
void MQTT_looP(void)
{
    int err =0;
    #if 1
    err = poll(&fds, 1, 30);
    if (err < 0) 
    {
	    printk("ERROR: poll %d\n", errno);
	    return ;
	}
    else
    {
        //printk("POLL ...\n");
    }
    #endif

    if ( (mqtt_keepalive_time_left(&client) <= 0) && (connected == true) )
    {
        printk("inside keepalive\n");
        err = mqtt_live(&client);
        //err=0;
        if ((err != 0) && (err != -EAGAIN)) 
        {
	        printk("ERROR: MQTT Keepalive %d\n", err);
	        return ;
        }
        else
        {
            printk("MQTT Keepalive sent\n");
        }
	}

    if ((fds.revents & POLLIN) == POLLIN) 
    {
        err = mqtt_input(&client);
	    if (err != 0) 
        {
		printk(">> ERROR: mqtt_input %d\n", err);
		return ;
		}
	}

    if ((fds.revents & POLLERR) == POLLERR) 
    {
	    printk("POLLERR\n");
	    return ;
	}

    if ((fds.revents & POLLNVAL) == POLLNVAL) 
    {
	    printk("POLLNVAL\n");
	    return ;
	}
}

///////////////////////////////////////////////////////////////////////////////////
// Start the MQTT protocol
int MQTT_Init()
{

	int err = 0;
        
    client.broker = SYNC_resp.Broker.host;
    client.client_id.utf8 = SYNC_resp.Broker.Client_Id; 
    client.user_name = SYNC_resp.Broker.user_name;
                
    err = client_init(&client);
    if (err != 0)
    {
        return err;
    }

	err = mqtt_connect(&client);
	if (err != 0) {
		printk("ERROR: mqtt_connect %d\n", err);
		return err;
	}
    printk("mqtt_connect done\n");

	err = fds_init(&client);
	if (err != 0) {
		printk("ERROR: fds_init %d\n", err);
		return err;
	}
    printk("fds_init done\n");
    return err;
}

#if 1
///////////////////////////////////////////////////////////////////////////////////
// this the Initialization os IoTConnect SDK
int IoTConnect_init(char *CpID, char *UniqueID, IOTConnectCallback CallBack, IOTConnectCallback TwinCallBack, char *Env)
{
    int retry;
    int res;

    char *Base_url;
    char *sync_resp;

    if(Flag_99)
    {
      printk("Inside flag_99\n");

        #if 0
        cJSON *SDK = cJSON_Parse(sdkoption);
        Discovery = (cJSON_GetObjectItem(SDK, "discoveryUrl"))->valuestring;
        Isdebug = (cJSON_GetObjectItem(SDK, "Isdebug"))->valueint;
      
        if(Isdebug)
            printk("\r\n\tINFO_IN04 [%s-%s] : Initializing…",CpID,UniqueID);
        if(strcmp(CpID,"") == 0){
            if(Isdebug)
                printk("\r\n\tERR_IN04 [%s-%s] : CpId can not be blank",CpID,UniqueID);
                return 1;
            }
        if(strcmp(UniqueID,"") == 0){
            if(Isdebug)
                printk("\r\n\tERR_IN05 [%s-%s] : UniqueId can not be blank",CpID,UniqueID);
                return 1;
            }
        K_MSEC(2000);
        #endif
        k_msleep(200);
        Base_url = get_base_url(HTTPS_HOSTNAME,CpID,Env);
        if (Base_url == NULL)
            return -1;
        if(Isdebug)
            printk("\r\n\tINFO_IN07 [%s-%s]: BaseUrl received", CpID, UniqueID);

        for (retry=0; retry<10;retry++)
        {
            k_msleep(200);
            sync_resp = Sync_call(CpID, UniqueID, Base_url);

            ENVT = Env;         CPID = CpID;
            Burl = Base_url;    UNIQUEID = UniqueID;
            res = Save_Sync_Responce(sync_resp);
            if (res == 1)
                break;
        }

        k_msleep(200);
        if ( !SYNC_resp.ds)               return 0;
        else                              return 1;
    }
}


///////////////////////////////////////////////////////////////////////////////////
/* Start MQTT init amd connect with client */
int IoTConnect_connect(void)
{
    int sleepCt, err;
      err = MQTT_Init();
      if (err != 0)
      {
        return err;
      }
      for (sleepCt = 0; sleepCt < 10; sleepCt++)
      {
        k_msleep(200);
      }
      MQTT_looP();
      return 0;
}


///////////////////////////////////////////////////////////////////////////////////
/* Setup TLS options on a given socket */
int tls_setup(int fd){
	int err;
	int verify;

	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};
        
        enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = OPTIONAL;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	return 0;
}


///////////////////////////////////////////////////////////////////////////////////
// you need to pass cpid , env and the HOST at GET_TEMPLATE
#define GET_TEMPLATE                                                              \
	"GET /api/sdk/cpid/%s/lang/M_C/ver/2.0/env/%s HTTP/1.1\r\n"               \
	"Host: %s\r\n"                                                            \
	"Content-Type: application/json; charset=utf-8\r\n"                       \
        "Connection: close\r\n\r\n"
char* get_base_url(char* Host, char *cpid, char *env){
    int err, fd, bytes;
    char *p;
    size_t off;
    struct addrinfo *IoT_res;
    struct addrinfo IoT_hints = {
            .ai_flags = AI_NUMERICSERV,
            .ai_socktype = SOCK_STREAM,
    };  
    char *Base_URL = NULL;
    char peer_addr[INET6_ADDRSTRLEN];

    printk("Get URL address ...\n");
 
    err = getaddrinfo(HTTPS_HOSTNAME, HTTPS_PORT, &IoT_hints, &IoT_res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return 0;
	}    
        
    //((struct sockaddr_in *)res->ai_addr)->sin_port = htons(IOTCONNECT_SERVER_HTTP_PORT);

    inet_ntop(IoT_res->ai_family, &((struct sockaddr_in *)(IoT_res->ai_addr))->sin_addr, peer_addr,
			INET6_ADDRSTRLEN);
	printk("Resolved %s (%s)\n", peer_addr, net_family2str(IoT_res->ai_family));

    fd = socket(IoT_res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fd == -1) {
            printk("Failed to open URL ADDR socket!\n");
            goto clean_up;
    }
    err = tls_setup(fd);
    if (err) {
            goto clean_up;
    }

	printk("Connecting to %s:%d\n", HTTPS_HOSTNAME,	ntohs(((struct sockaddr_in *)(IoT_res->ai_addr))->sin_port));
    err = connect(fd, IoT_res->ai_addr, IoT_res->ai_addrlen);
    if (err) {
            printk("connect() failed, err: %d\n", errno);
            goto clean_up;
    }
    printk("  .. OK\n");
    //char send_buf[2047 + 1];

    //(void)close(fd);
    //goto clean_up;


    int HTTP_HEAD_LEN = snprintf(send_buf,
	    500, /*total length should not exceed MTU size*/
	    GET_TEMPLATE, cpid, env,
	    HTTPS_HOSTNAME
            );
    off = 0;  
    do {
            bytes = send(fd, &send_buf[off], HTTP_HEAD_LEN - off, 0);
            if (bytes < 0) {
                    printk("send() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
	} while (off < HTTP_HEAD_LEN);

    off = 0;
    do {
            bytes = recv(fd, &recv_buf[off], MAXLINE - off, 0);
            if (bytes < 0) {
                    printk("recv() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
	} while (bytes != 0 );

    p = strstr(recv_buf, "\r\n{");
    cJSON *root = NULL;
    root = cJSON_Parse(p);
    Base_URL = (cJSON_GetObjectItem(root, "baseUrl"))->valuestring;
    close(fd);
    if (Base_URL != NULL)
    {
        strcat(Base_URL,"sync");
        return Base_URL;
    }
    else
    {
        return NULL;
    }

clean_up:{
    freeaddrinfo(IoT_res);
    cJSON_Delete(root);
    }
    return NULL;

}



///////////////////////////////////////////////////////////////////////////////
// you need to pass remain_url ,host, post_data_lan and post_data
#define POST_TEMPLATE                                                         \
	"POST /api/2.0/agent/sync? HTTP/1.1\r\n"                              \
	"Host: %s\r\n"                                                        \
	"Content-Type: application/json; charset=utf-8\r\n"                   \
        "Connection: keep-alive\r\n"                                          \
        "Content-length: %d\r\n\r\n"                                          \
	"%s"

char* Sync_call(char *cpid, char *uniqueid, char *base_url){
    int err;
    int fdP;
    char *Sync_call_resp;
    int bytes;
    size_t off;
    struct addrinfo *res;
    struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
    };  
    
    char *AgentHost ;
    for(int a=0;a<3;a++)
        AgentHost = strsep(&base_url,"//");

    err = getaddrinfo(AgentHost, NULL, &hints, &res);
    k_msleep(1000);
    ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(IOTCONNECT_SERVER_HTTP_PORT);
    fdP =socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fdP == -1) {
            printk("Failed to open SYNC socket!\n");
            goto clean_up;
    }

    err = tls_setup(fdP);
    if (err) {
            goto clean_up;
    }
   printk("\n\nConnecting to %s", AgentHost);
    err = connect(fdP, res->ai_addr, res->ai_addrlen);
    if (err) {
            printk("connect() failed, err: %d\n", errno);
            goto clean_up;
    }
    printk("  .. OK\n");
    char post_data[800] = "{\"cpId\":\"";
          strcat(post_data,cpid);
          strcat(post_data,"\",\"uniqueId\":\"");
          strcat(post_data,uniqueid);
          strcat(post_data,"\",\"option\":{\"attribute\":false,\"setting\":false,\"protocol\":true,\"device\":false,\"sdkConfig\":false,\"rule\":false}}");

    //char send_buf[MAXLINE + 1];
    int HTTP_POST_LEN = snprintf(send_buf,
	    1024, /*total length should not exceed MTU size*/
	    POST_TEMPLATE, AgentHost,
	    strlen(post_data), post_data
           );
    off = 0;  // 
    do {
            bytes = send(fdP, &send_buf[off], HTTP_POST_LEN - off, 0);
             if (bytes < 0) {
                    printk("send() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
	} while (off < HTTP_POST_LEN);

      off = 0;
    do {
            bytes = recv(fdP, &recv_buf[off], MAXLINE - off, 0);
            if (bytes < 0) {
                    printk("recv() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
            if (off >= 1025)
             break;
	} while (bytes != 0); /* peer closed connection */ 

    Sync_call_resp = strstr(recv_buf, "\r\n{");

clean_up:
	freeaddrinfo(res);
    close(fdP);
    return Sync_call_resp;
}

///////////////////////////////////////////////////////////////////////////////////
// this functoin will save syncResp in cache memory of device 
int Save_Sync_Responce(char *sync_data){
    cJSON *root = NULL;
    cJSON *Sync_Res_Json = NULL;
    cJSON *P = NULL, *sc = NULL;
    root = cJSON_Parse(sync_data);

    Sync_Res_Json = cJSON_GetObjectItemCaseSensitive(root, "d");
    SYNC_resp.ds = (cJSON_GetObjectItem(Sync_Res_Json, "ds"))->valueint;
    printk("\r\n\tDevice : %s Status :",UNIQUEID);  
    if(SYNC_resp.ds == 0)
    {
          printk("  .. OK");
          SYNC_resp.cpId = (cJSON_GetObjectItem(Sync_Res_Json, "cpId"))->valuestring;
          SYNC_resp.dtg = (cJSON_GetObjectItem(Sync_Res_Json, "dtg"))->valuestring;
          SYNC_resp.ee = (cJSON_GetObjectItem(Sync_Res_Json, "ee"))->valueint;
          SYNC_resp.rc = (cJSON_GetObjectItem(Sync_Res_Json, "rc"))->valueint;
          SYNC_resp.at = (cJSON_GetObjectItem(Sync_Res_Json, "at"))->valueint;
          sc = cJSON_GetObjectItemCaseSensitive(Sync_Res_Json, "sc");
          SYNC_resp.df = (cJSON_GetObjectItem(sc, "df"))->valueint;
          P = cJSON_GetObjectItemCaseSensitive(Sync_Res_Json, "p");
          SYNC_resp.Broker.name = (cJSON_GetObjectItem(P, "n"))->valuestring;
          SYNC_resp.Broker.Client_Id = (cJSON_GetObjectItem(P, "id"))->valuestring;
          SYNC_resp.Broker.host = (cJSON_GetObjectItem(P, "h"))->valuestring;
          SYNC_resp.Broker.user_name = (cJSON_GetObjectItem(P, "un"))->valuestring;
          SYNC_resp.Broker.pass = (cJSON_GetObjectItem(P, "pwd"))->valuestring;
          SYNC_resp.Broker.sub_Topic = (cJSON_GetObjectItem(P, "sub"))->valuestring;
          SYNC_resp.Broker.pub_Topic = (cJSON_GetObjectItem(P, "pub"))->valuestring;
          printk("\r\n\tSync_Response_Data Saved\n");
    }
    else 
    if(SYNC_resp.ds == 1)
    {
        if(Isdebug)
         printk("\r\n\tINFO_IN09 [%s-%s] : Response Code : 1 'DEVICE_NOT_REGISTERED'",CPID,UNIQUEID);
        //return ;
    }
    else 
    if(SYNC_resp.ds == 2)
    {
        if(Isdebug)
            printk("\r\n\tINFO_IN10 [%s-%s] : Response Code : 2 'AUTO_REGISTER'",CPID,UNIQUEID);
        //return ;
    }
    else 
    if(SYNC_resp.ds == 3)  
    {
        if(Isdebug)
            printk("\r\n\tINFO_IN11 [%s-%s] : Response Code : 3 'DEVICE_NOT_FOUND'",CPID,UNIQUEID);
        //return ;
    }
    else 
    if(SYNC_resp.ds == 4)
    {
        if(Isdebug)
            printk("\r\n\tINFO_IN12 [%s-%s] : Response Code : 4 'DEVICE_INACTIVE'",CPID,UNIQUEID);
        //return ;
    }
    else 
    if(SYNC_resp.ds == 5)
    {
        if(Isdebug)
            printk("\r\n\tINFO_IN13 [%s-%s] : Response Code : 5 'OBJECT_MOVED'",CPID,UNIQUEID);
        //return ;
    }
    else 
    if(SYNC_resp.ds == 6)
    {
        if(Isdebug)
            printk("\r\n\tINFO_IN014 [%s-%s] : Response Code : 6 'CPID_NOT_FOUND'",CPID,UNIQUEID);
        //return ;
    }
    else
    {
        if(Isdebug)
        {
            printk("\r\n\tINFO_IN15 [%s-%s] : Response Code : 'NO_RESPONSE_CODE_MATCHED'",CPID,UNIQUEID);
            printk("\r\n\tERR_IN010 [%s-%s] : Device information not found",CPID,UNIQUEID);
        }
        //return ;
    }
    //cJSON_Delete(root);
    if (SYNC_resp.Broker.host[0] != NULL)
        return 1;
    else
        return 0;

}


////////////////////////////////////////////////////////////////////////////////////
// Received data in callback from C2D 
void data_print(uint8_t *prefix, uint8_t *data, char *topic, size_t len){
    char buf[len + 1];
    cJSON *root,*root2,*data_R;
    char *SMS, *cmd;
    memcpy(buf, data, len);
    buf[len] = 0;
    //printk("topic test1:\n",topic);
    if (strlen(buf) > 5){
    
        //printk("topic test2:\n",topic);
        
        if(! strncmp(topic,"$iothub/twin/res/",17)){ 
                       
             root = cJSON_Parse(buf);
             cJSON_AddStringToObject(root,"uniqueId",UNIQUEID);
             SMS = cJSON_PrintUnformatted(root);         
             (*TwinUpdateCallback)(SMS);
             k_msleep(10);
             
             cJSON_Delete(root);
             free(SMS);
        }
        else if(! strncmp(topic,"$iothub/twin/PATCH/properties/",30)){        
             root = cJSON_CreateObject();
             root2 = cJSON_Parse(buf);
             cJSON_AddItemToObject(root,"desired",root2);
             cJSON_AddStringToObject(root,"uniqueId",UNIQUEID);
             SMS = cJSON_PrintUnformatted(root);   
             (*TwinUpdateCallback)(SMS);
             k_msleep(10);
             
             cJSON_Delete(root);
             free(SMS);
        }
        else {
          root = cJSON_Parse(buf);
          cmd = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
          if( (!strcmp(cmd,"0x01")) || ( !strcmp(cmd,"0x02")) ){
             if(Isdebug){
                if(!strcmp(cmd,"0x01"))
                    printk("\r\n\tINFO_CM01 [%s-%s] : Command : 0x01 : STANDARD_COMMAND",CPID,UNIQUEID);
                if(!strcmp(cmd,"0x02 "))
                     printk("\r\n\tINFO_CM02 [%s-%s] : Command : 0x02 : FIRMWARE_UPDATE",CPID,UNIQUEID);
                }
              data_R = cJSON_GetObjectItemCaseSensitive(root, "data");
              SMS = cJSON_PrintUnformatted(data_R);
              (*DeviceCallback)(SMS);
              k_msleep(10);
             
             cJSON_Delete(root);
             free(SMS);
          }
          else {
              Received_cmd(buf);         
          }
          k_msleep(10);
       }
    }
    else ;
}

///////////////////////////////////////////////////////////////////////////////////
// Get All twin property from C2D
void GetAllTwins(void){
    data_publish(&client,twinResponsePubTopic, 1, " ", strlen(" "));
    if(Isdebug)
        printk("\r\n\tINFO_TP02 [%s %s] : twin properties l request sent successfully\n",CPID,UNIQUEID);
    return ;
}


///////////////////////////////////////////////////////////////////////////////////
//disconnect SDk from IoTConnect
int IoTConnect_abort(void){
    int sd = mqtt_disconnect(&client);  Flag_99 = false; 
     k_msleep(100);
    //if (sd == 0)
      //printk("\r\n\tDevice [%s %s] disconnected\n",CPID,UNIQUEID);
    //else
    if (sd != 0)
      printk("\r\n\tERROR disconnectiong [%s %s]\n ",CPID,UNIQUEID);
   return 0;
}

int errPub;

///////////////////////////////////////////////////////////////////////////////////
// Get Sensor data and send to cloud
int SendData(char *Attribute_json_Data)
{
    int err;
    // if(Flag_99)
    // { 
        char *NowTime = Get_Time();
        long int Timediff = GetTimeDiff(NowTime, LastTime);
        if (SYNC_resp.df < Timediff) 
        {
            if(!SYNC_resp.ds)
            {
                cJSON *To_HUB_json, *sdk, *device, *device2, *data1, *Device_data1;
                char *To_HUB_json_data = " ";
                cJSON *root = cJSON_Parse(Attribute_json_Data);
                To_HUB_json = cJSON_CreateObject();
                if (To_HUB_json == NULL)
                {
                  printk("Unable to allocate To_HUB_json Object\n");
                  return -1;    
                }
                cJSON_AddStringToObject(To_HUB_json, "cpId", SYNC_resp.cpId);
                cJSON_AddStringToObject(To_HUB_json, "dtg", SYNC_resp.dtg);
                cJSON *parameter = cJSON_GetArrayItem(root, 0);

                cJSON_AddStringToObject(To_HUB_json, "t", cJSON_GetObjectItem(parameter, "time")->valuestring);
                cJSON_AddNumberToObject(To_HUB_json, "mt", 0);
                cJSON_AddItemToObject(To_HUB_json, "sdk", sdk = cJSON_CreateObject());
                cJSON_AddStringToObject(sdk,"l","M_C");
                cJSON_AddStringToObject(sdk,"v","2.0");
                cJSON_AddStringToObject(sdk,"e",ENVT);
                cJSON_AddItemToObject(To_HUB_json, "d", device = cJSON_CreateArray());

                int parameters_count = cJSON_GetArraySize(root);    

                for (int i = 0; i < parameters_count; i++) 
                {
                    cJSON *parameter = cJSON_GetArrayItem(root, i);
                    cJSON_AddItemToArray(device, Device_data1 = cJSON_CreateObject());
                    cJSON_AddStringToObject(Device_data1, "id", cJSON_GetObjectItem(parameter, "uniqueId")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "dt", cJSON_GetObjectItem(parameter, "time")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "tg", "");
                    cJSON_AddItemToObject(Device_data1, "d", device2 = cJSON_CreateArray());
                    data1 = cJSON_GetObjectItem(parameter, "data");
                    cJSON_AddItemToArray(device2,data1);
                }
                To_HUB_json_data =  cJSON_PrintUnformatted(To_HUB_json);
                printk("\r\n\tPublishing data...\n");
                errPub = data_publish(&client, SYNC_resp.Broker.pub_Topic, 1, To_HUB_json_data, strlen(To_HUB_json_data));
                if ( errPub == 0)
                {
                    printk("\r\n\tINFO_SD01 [%s %s] : publish data id %d\n",CPID, UNIQUEID, mid_num);
                    pubAck = false;
                } 
                else
                {
                    printk("\r\n\tERR_SD01 [%s %s] : Publish data failed err %d: MQTT connection not found\n", CPID, UNIQUEID, errPub);
                }


                for(int ss=0;ss<25;ss++)
                    LastTime[ss] = NowTime[ss];
                k_msleep(10);
                cJSON_Delete(To_HUB_json);
                return 1;

            }  //if(ds)
        }   //if(df)
    
    else
    {    //else of if(Flag_99)
        if(Isdebug)
        printk("\r\n\tINFO_DC01 [%s-%s] : Device already disconnected",CPID,UNIQUEID);
    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////////
//This will UpdateTwin property to IoTConnect
void UpdateTwin(char *key,char *value){
    char *Twin_Json_Data;
    cJSON *root;
    root  = cJSON_CreateObject();

    cJSON_AddStringToObject(root, key, value);
    Twin_Json_Data = cJSON_PrintUnformatted(root);
 
    printk("json format of Twin_Json_Data = %s",Twin_Json_Data);
    if ( ! data_publish(&client, twinPropertyPubTopic, 0, Twin_Json_Data, strlen(Twin_Json_Data))){
        if(Isdebug)
              printk("\r\n\tINFO_TP01 [%s-%s] : Twin property updated successfully",CPID,UNIQUEID);
        }

    cJSON_Delete(root);
    free(Twin_Json_Data);
}


///////////////////////////////////////////////////////////////////////////////////
// Received command to control SDK
void Received_cmd(char *in_cmd){

    cJSON *root = NULL;
    char *cmdValue, payLoad;
    root = cJSON_Parse(in_cmd);

    cmdValue = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
    if( !strcmp(cmdValue,"0x10")){
        if(Isdebug)
              printk("\r\n\tINFO_CM03 [%s-%s] : Command : 0x10 : ATTRIBUTE_UPDATE",CPID,UNIQUEID);
        return ;
    }

    else if( !strcmp(cmdValue,"0x11")){
        if(Isdebug)
              printk("\r\n\tINFO_CM04 [%s-%s] : Command : 0x11 : SETTING_UPDATE",CPID,UNIQUEID);
        return ;
    }

    else if( !strcmp(cmdValue,"0x12")){
        mqtt_disconnect(&client);  k_msleep(100);
                if(Isdebug)
              printk("\r\n\tINFO_CM05 [%s-%s] : Command : 0x12 : PASSWORD_UPDATE",CPID,UNIQUEID);
        payLoad = Sync_call(CPID,UNIQUEID,Burl);
        Save_Sync_Responce(payLoad);MQTT_Init();
        
    }
    else if( !strcmp(cmdValue,"0x13")){
        if(Isdebug)
              printk("\r\n\tINFO_CM06 [%s-%s] : Command : 0x13 : DEVICE_UPDATE",CPID,UNIQUEID);
        return ;
    }
    else if( !strcmp(cmdValue,"0x15")){
        if(Isdebug)
              printk("\r\n\tINFO_CM07 [%s-%s] : Command : 0x15 : RULE_UPDATE",CPID,UNIQUEID);
        return ;
    }
    else if( !strcmp(cmdValue,"0x99")){
        if(Isdebug)
              printk("\r\n\tINFO_CM08 [%s-%s] : Command : 0x99 : STOP_SDK_CONNECTION",CPID,UNIQUEID);
         mqtt_disconnect(&client);  Flag_99 = false;
         return ;
    }   
}


///////////////////////////////////////////////////////////////////////////////////
// this will calculate the difference between two datetime
int GetTimeDiff(char newT[25], char oldT[25]){
    time_t NEW,OLD;
    struct tm new_date;
    struct tm old_date;  
    unsigned int DHour,DMin,DSec;
 
    new_date.tm_mday = ((newT[8]-'0')*10 + (newT[9]-'0'));    new_date.tm_mon = ((newT[5]-'0')*10 + (newT[6]-'0'));
    new_date.tm_year = ((newT[3]-'0')*1000 +(newT[2]-'0')*100 +(newT[1]-'0')*10 + (newT[0]-'0'));  
    new_date.tm_hour = ((newT[11]-'0')*10 + (newT[12]-'0'));  new_date.tm_min = ((newT[14]-'0')*10 + (newT[15]-'0'));
    new_date.tm_sec = ((newT[17]-'0')*10 + (newT[18]-'0'));
  
    old_date.tm_mday = ((oldT[8]-'0')*10 + (oldT[9]-'0'));    old_date.tm_mon = ((oldT[5]-'0')*10 + (oldT[6]-'0'));
    old_date.tm_year = ((oldT[3]-'0')*1000 +(oldT[2]-'0')*100 +(oldT[1]-'0')*10 + (oldT[0]-'0'));  
    old_date.tm_hour = ((oldT[11]-'0')*10 + (oldT[12]-'0'));  old_date.tm_min = ((oldT[14]-'0')*10 + (oldT[15]-'0'));
    old_date.tm_sec = ((oldT[17]-'0')*10 + (oldT[18]-'0'));
  
    NEW= mktime(&new_date);
    OLD = mktime(&old_date);
    while (old_date.tm_sec > new_date.tm_sec) {
        --new_date.tm_min;
        new_date.tm_sec += 60;
    }

    DSec = new_date.tm_sec - old_date.tm_sec;
    while (old_date.tm_min > new_date.tm_min) {
        --new_date.tm_hour;
        new_date.tm_min += 60;
    }
    DMin = new_date.tm_min - old_date.tm_min;
    DHour = new_date.tm_hour - old_date.tm_hour;
  
    unsigned int TIMEDIFF = (DHour*60*60) +(DMin*60) +(DSec);
    return TIMEDIFF;
}    


///////////////////////////////////////////////////////////////////////////////////
// this will send the ACK of receiving Commands
void SendAck(char *Ack_Data, int messageType){
    cJSON *Ack_Json2,*sdk_info,*device_input;
    char *Ack_Json_Data;
    Ack_Json2 = cJSON_CreateObject();
    if (Ack_Json2 == NULL){
        printk("\nUnable to allocate Ack_Json2 Object in SendAck");
        return ;    
    }
    
    cJSON_AddStringToObject(Ack_Json2, "uniqueId",UNIQUEID);
    cJSON_AddStringToObject(Ack_Json2, "cpId",CPID);
    cJSON_AddStringToObject(Ack_Json2, "t",Get_Time());
    cJSON_AddNumberToObject(Ack_Json2, "mt",messageType);
    cJSON_AddItemToObject(Ack_Json2, "sdk", sdk_info = cJSON_CreateObject());
    cJSON_AddStringToObject(sdk_info, "l","M_C");
    cJSON_AddStringToObject(sdk_info, "v","2.0");
    cJSON_AddStringToObject(sdk_info, "e",ENVT);
    cJSON *root = cJSON_Parse(Ack_Data);
    cJSON_AddItemToObject(Ack_Json2, "d", root);
    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json2);

    if ( ! data_publish(&client, SYNC_resp.Broker.pub_Topic, 1, Ack_Json_Data, strlen(Ack_Json_Data))){
        printk("\n\t Ack_Json_Data Publish ");
    }   
    return ;
}

#endif


/* Initialize AT communications */
static int at_comms_init(void)
{
	int err;
	err = nrf_modem_lib_init();
	if (err) {
		printk("Modem library initialization failed, error: %d\n", err);
		return 0;
	}

}

char *Attribute_json_Data = " ";
int ct_count;

static K_SEM_DEFINE(pdn_ipv6_up_sem_1, 0, 1);

void IoT_Connect_main(void)
{
    int err; 
    int del;
    printk("inside IoT_Connect_main");
    ct_count=0; 
    Flag_99 = true;
     if(GSM_MODEM_FLAG == true)
         {
            GSM_MODEM_FLAG = false;
        err = at_comms_init();
        if (err) 
        {
            return ;
        }
    
    
	#if !defined(CONFIG_SAMPLE_TFM_MBEDTLS)
		/* Provision certificates before connecting to the LTE network */
		LOG_INF("Provision certificates before connecting to the LTE network \n");
		err = cert_provision();
		if (err) {
			return 0;
		}
	#endif

    #if defined(CONFIG_PROVISION_CERTIFICATES)
    /* NOT USED ON THIS RELEASE -- USED "MQTT TOKEN" TO CONNECT "IoT Connect" CLOUD*/
    err = nrf_cert_store_save_device_cert();

    if (err) 
	{
		return ;
	}
    #endif
         }
    /*starting connection ...*/
    //IoT_start:
    LOG_INF("Waiting for network.. ");
    err = lte_lc_init_and_connect();
    if (err) 
	{
		LOG_ERR("Failed to connect to the LTE network, err %d\n", err);
		return ;
	}
    LOG_INF("OK\n");

	/*
	## Prerequisite params to run this sample code input in IoTConnect_config.h
	- IOTCONNECT_DEVICE_CP_ID      	:: It need to get from the IoTConnect platform. 
	- IOTCONNECT_DEVICE_UNIQUE_ID  	:: Its device ID which register on IotConnect platform and also its status has Active and Acquired
	- IOTCONNECT_DEVICE_ENV        	:: You need to pass respective environment of IoTConnecct platform
	*/
    k_msleep(2000);
    printk("GSM Done\n");
    
    err = IoTConnect_init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, DeviceCallback, TwinUpdateCallback, IOTCONNECT_DEVICE_ENV);
    if (err) 
	{
		LOG_ERR("Failed Init IoTConnect SDK");
	}
    else
    {

	    /*
	    Type    : Public Method "IoTConnect_connect()"
	    Usage   : To connect with IoTConnect MQTT broker
	    */
	    err = IoTConnect_connect();
        if (err) 
	    {
	    	LOG_ERR("Failed connect MQTT IoTConnect CLOUD\n");
	    }
        
       
    }
    Publish_Data();
    k_msleep(2500);
    err = IoTConnect_abort();
     if (err) {
        printk("Failed to Abort IoTConnect SDK");
        return ;
     }
     k_msleep(3000);

        printk("Powering OFF LTE\n");
        
        lte_lc_power_off();
        k_msleep(5000);

     

    // if (err != 0)
    // {
    //     //printk("resuming starting procedure within 60 seconds...\n");
    //     //printk("Powering OFF LTE\n");
    //     k_msleep(2000);
    //     //lte_lc_power_off();
    //     // for (del=0; del < 600; del++)
    //     // {
    //     //     k_msleep(100);
    //     //     for (int fake=0; fake < 10000; fake++);
    //     // }
    //     goto IoT_start;
    // }

	/*
	Type    : Public Method "getAllTwins()"
	Usage   : To get all the twin properties Desired and Reported
	Output  : All twin property will receive in above callback function "TwinUpdateCallback()"
	NOT USED ON THIS RELEASE */
	//GetAllTwins();

// 	while(ct_count < 2)
//     {
//         err=0;
//         k_msleep(1000);
// 		MQTT_looP();
        
//         char *NowTime = Get_Time();
//         long int Timediff = GetTimeDiff(NowTime, LastTime);
//         if ( (SYNC_resp.df < Timediff) && (connected == true) )
//         {
// 	        Attribute_json_Data = Sensor_data();
//             err = SendData(Attribute_json_Data);
//         }
//         err = 0;
//         if (pubAck == true)
//         {   
//             pubAck = false;
//             printk("Publish ACK DONE, wait 15 seconds before disconnect\n");
//             #if 1
//             for (del=0; del < 150; del++)
//             {
//                 k_msleep(100);
//                 for (int fake=0; fake < 10000; fake++);
//             }
//             //IoTConnect_abort();
//             for (del=0; del < 100; del++)
//             {
//                 k_msleep(100);
//                 if (connected == false)
//                 {
//                     k_msleep(2000);
//                     break;
//                 }
//                 for (int fake=0; fake < 10000; fake++);
//             }
//             resumeIoT:
//             // printk("Powering OFF LTE\n");
//             // if (connected == false)
//             // lte_lc_power_off();

//             // for (del=0; del < 600; del++)
//             // {
//             //     k_msleep(100);
//             //     for (int fake=0; fake < 10000; fake++);
//             // }
//             printk("\nResuming connection\nWaiting for LTE network... ");
//             err = lte_lc_init_and_connect();
//             if (err) 
//             {
//                 printk("Failed to connect to the LTE network, err %d\n", err);
//                 break;
//             }
//             printk("OK\n");
//             Flag_99 = true;
//             k_msleep(2000);
//             err = IoTConnect_init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, DeviceCallback, TwinUpdateCallback, IOTCONNECT_DEVICE_ENV);
//             if (err) 
//             {
//                 printk("Failed to Init IoTConnect SDK, %d\n", err);
//             }
//             else
//             {
//                 err = IoTConnect_connect();
//                 if (err) 
//                 {
//                     printk("Failed to Connect IoTConnect cloud, %d\n", err);
//                 }
//             }
//             //GetAllTwins();
//             //pubAck = false;
//             #endif
//         }
        
//         if (err != 0)
//         {
//             k_msleep(1000);
//             printk(">>>>>>>>>>>> RESUME IOT\n");
//             goto resumeIoT;
//         }

// 	//k_msleep(1000);
// 	}
//     while(1)
//     {
//         if (pubAck == true);
//            break;
//         k_msleep(100);
//     }
//     k_msleep(1000);
//     printk("*******************************************************\n");
// 	printk("SAMPLE ENDED, DISCONNECT ...\n\n");
//     /*
// 	Type    : Public Method "IoTConnect_abort()"
// 	Usage   : Disconnect the device from cloud
// 	Output  : 
// 	Input   : 
// 	Note : It will disconnect the device after defined time 
// 	*/ 
//     //  err = IoTConnect_abort();
//     //  if (err) {
//     //     printk("Failed to Abort IoTConnect SDK");
//     //  }
//    // printk("Powering off MODEM");
//     //lte_lc_power_off();
//     k_msleep(2000);
//     printk(">>>> SAMPLE STOPPED\n");
//     return ;
}

 void Publish_Data(){
		MQTT_looP();
        
		// all sensors data will be formed in JSON format and will be published by SendData() function 
		Attribute_json_Data = Sensor_data();

		/*
		Type    : Public Method "sendData()"
		Usage   : To publish the D2C data 
		Output  : 
		Input   : Predefined data object 
		*/      
		SendData(Attribute_json_Data);
		
        k_msleep(2000);
		 
    }

/*
Type    : Callback Function "TwinUpdateCallback()"
Usage   : Manage twin properties as per business logic to update the twin reported property
Output  : Receive twin properties Desired, Reported
Input   : 
*/
void TwinUpdateCallback(char *payload) {      
    char *key = NULL, *value = NULL;
    printk("\n Twin_msg payload is >>  %s", payload);
    
    cJSON *root = cJSON_Parse(payload);        
    cJSON *D = cJSON_GetObjectItem(root, "desired");
    if(D) {
        cJSON *device = D->child;
        while (device){
            if(! strcmp(device->string,"$version")){
       
            }
            else{
                key = device->string;
                value = (cJSON_GetObjectItem(D, key))->valuestring;
                
               /*
                Type    : Public Method "updateTwin()"
                Usage   : Upate the twin reported property
                Output  : 
                Input   : "key" and "value" as below
                          // String key = "<< Desired property key >>"; // Desired proeprty key received from Twin callback message
                          // String value = "<< Desired Property value >>"; // Value of respective desired property
               */    
                UpdateTwin(key,value);
            }
            device = device->next;
        }		
    }
}

/*
Type    : Callback Function "DeviceCallback()"
Usage   : Firmware will receive commands from cloud. You can manage your business logic as per received command.
Output  : Receive device command, firmware command and other device initialize error response
Input   :  
*/
void DeviceCallback(char *payload) {      
    //printk("Payload is this: %s\n", payload);
    cJSON *Ack_Json, *sub_value, *in_url;
    int Status = 0,magType=0;
    char *cmd_ackID, *Cmd_value, *Ack_Json_Data, *cmd_Uni="";
    char *command = "";
    char data_to_print[120+1];
    char *find;
    int len;

    find = strstr(payload, "guid");
    len = (find-payload) - 6;
    if (len>120)
        len = 120;
    memset(data_to_print, 0, sizeof(data_to_print));
    memcpy(&data_to_print, &payload[4], len);
    printk("\n Cmd_msg >> %s", &data_to_print);   

    cJSON *root = cJSON_Parse(payload);
    cmd_ackID = (cJSON_GetObjectItem(root, "ackId"))->valuestring;
    Cmd_value = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
    command   = (cJSON_GetObjectItem(root, "command"))->valuestring;

    //printk("Cmd_Value is: %s\n", Cmd_value);
    //printk("Command_Value is: %s\n", command);

    //if( !strcmp(command,"0x20"))
	//{
       // printk("Command executed\n");
    //}
     // Convert the string to an unsigned long

    // unsigned long Sleep_Variable;
    // // Sleep_Variable = strtoul(Cmd_value, NULL, 0);
    // // sleepTime = Sleep_Variable*1000*60;

    if( !strcmp(Cmd_value,"0x16"))
	{
		sub_value = cJSON_GetObjectItem(root,"command");
		int CMD = sub_value->valueint;
		if(CMD == 1){
			printk("\r\n\t ** Device Connected ** \n");
		} 
		else if(CMD == 0) 
		{
			printk("\r\n\t ** Device Disconnected ** \n");
		}
		return;
    }

    if( !strcmp(Cmd_value,"0x01") )
	{
       
    

		Status = 6; magType = 5;
	}

    else if( !strcmp(Cmd_value,"0x02") ) 
	{
        Status = 7; magType = 11;
    	sub_value = cJSON_GetObjectItem(root,"urls");
		if(cJSON_IsArray(sub_value)){
            in_url = cJSON_GetArrayItem(sub_value, 0);
            sub_value = cJSON_GetObjectItem(in_url, "uniqueId");
            if(cJSON_IsString(sub_value))
			cmd_Uni = sub_value->valuestring;
		}
    } else { }

    Ack_Json = cJSON_CreateObject();
    if (Ack_Json == NULL)
	{
        printk("\nUnable to allocate Ack_Json Object in Device_CallBack");
        return ;    
    }
    cJSON_AddStringToObject(Ack_Json, "ackId",cmd_ackID);
    cJSON_AddStringToObject(Ack_Json, "msg","");
    cJSON_AddStringToObject(Ack_Json, "childId",cmd_Uni);
    cJSON_AddNumberToObject(Ack_Json, "st", Status);

    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json);
    
    /*
    Type    : Public Method "sendAck()"
    Usage   : Send firmware command received acknowledgement to cloud
      - status Type
		st = 6; // Device command Ack status 
		st = 7; // firmware OTA command Ack status 
        st = 4; // Failed Ack
      - Message Type
		msgType = 5; // for "0x01" device command 
        msgType = 11; // for "0x02" Firmware command
    */  
    SendAck(Ack_Json_Data, magType);
    cJSON_Delete(Ack_Json);
}

/*! Object  - need to read and setup all sensor(Attribute) data in JSON format
 *  \param  - None
 *  \return - None
 */
char *Sensor_data(void){

    cJSON *Attribute_json = NULL;
    cJSON *Device_data1 = NULL;
    cJSON *Data = NULL, *Data1= NULL;

    Attribute_json = cJSON_CreateArray();
    if (Attribute_json == NULL)
	{
        printk("Unable to allocate Attribute_json Object\n");
        return ;    
    }
    cJSON_AddItemToArray(Attribute_json, Device_data1 = cJSON_CreateObject());
    cJSON_AddStringToObject(Device_data1, "uniqueId",IOTCONNECT_DEVICE_UNIQUE_ID);
    cJSON_AddStringToObject(Device_data1, "time", Get_Time());
    cJSON_AddItemToObject(Device_data1, "data", Data = cJSON_CreateObject());
    //cJSON_AddNumberToObject(Data,"Humidity", 20 );
    //cJSON_AddNumberToObject(Data, "Temperature", 11);
    static struct sensor_value weight;
    //measure_weight();
    //float weight_grams = weight.val1 + weight.val2;
    cJSON_AddNumberToObject(Data, "Weight", weight_grams);
    //cJSON_AddNumberToObject(Data, "Weight", 11);
    //cJSON_AddNumberToObject(Data, "Battery", battery_data_str);
    //char* s_batt = malloc(strlen(battery_data_str));
    //strcpy(s_batt, battery_data_str);
    //printk("value: %s\n",s_batt);
    cJSON_AddStringToObject(Data, "BatteryStatus", (char*)battery_data_str);
    //cJSON_AddNumberToObject(Data, "Battery_Voltage", truncatedNumber);
    //cJSON_AddNumberToObject(Data,"Battery_Percentage",battery_percentage);
     //cJSON_AddNumberToObject(Data, "Battery", 80);
    //free(s_batt);
   //cJSON_AddStringToObject(Data, "Battery", "Hello!3@3.?");
   
    //cJSON_AddNumberToObject(Data,"Weight", 60 );
    //cJSON_AddNumberToObject(Data, "Weight2", 20);
    //cJSON_AddNumberToObject(Data, "ct", ++ct_count);
    printk("Prepare data to publish ct_count=%d\n", ct_count);
    //cJSON_AddItemToObject(Data, "Gyroscope", Data1 = cJSON_CreateObject());
    //cJSON_AddNumberToObject(Data1, "x",  128);
    //cJSON_AddStringToObject(Data1, "y",  100);
    //cJSON_AddNumberToObject(Data1, "z",  318);
	
	/*
	 Non Gateway device input data format Example:
		String data = [{
			"uniqueId": "<< Device UniqueId >>",
			"time" : "<< date >>",
			"data": {}
		}];
	- time : Date format should be as defined # "2021-01-24T10:06:17.857Z"
	- data : JSON data type format # {"temperature": 15.55, "gyroscope" : { 'x' : -1.2 }}
	*/
    char *msg = cJSON_PrintUnformatted(Attribute_json);
    cJSON_Delete(Attribute_json);
    return  msg;
}


