<?php

namespace Pommes\Security\Helper;

use Credis_Client;

class Data extends \Magento\Framework\App\Helper\AbstractHelper {

    const CONFIG_PATH_ENABLED = 'pommes_security/general/enabled';
    const CONFIG_PATH_PROTECTION_LIST = 'pommes_security/general/protection_list';
    const CONFIG_PATH_EMAIL = 'pommes_security/general/notification_mail';

    const CONFIG_PATH_REDIS_HOST = 'pommes_security/redis_config/host';
    const CONFIG_PATH_REDIS_PORT = 'pommes_security/redis_config/port';
    const CONFIG_PATH_REDIS_DATABASE = 'pommes_security/redis_config/database';
    const CONFIG_PATH_REDIS_MAX_CONN_TRIES = 'pommes_security/redis_config/max_connection_tries';
    const CONFIG_PATH_REDIS_TIMEOUT = 'pommes_security/redis_config/timeout';


    /**
     * Check if module is activated for current store
     */
    public function isEnabled() {
        return (int)$this->scopeConfig->getValue(self::CONFIG_PATH_ENABLED) === 1;
    }

    /**
     * Get list of actions we want to protect from spamming
     *
     * Format:
     * action-name|max-requests|max-request-within-seconds|lock-time-when-max-request-reached,
     * action-name|max-requests|max-request-within-seconds|lock-time-when-max-request-reached,
     * action-name|max-requests|max-request-within-seconds|lock-time-when-max-request-reached
     */
    public function getProtectionListAsArray() {

        /* Returned array */
        $protections = array();

        /* Gather protections */
        $protection_config = $this->getStoreConfigAsArray(self::CONFIG_PATH_PROTECTION_LIST);
        foreach ($protection_config as $protection) {

            /* Check for content */
            if(strlen($protection) > 4) {

                /* Split data */
                $protection_data = explode('|', $protection);
                if(count($protection_data) === 4) {

                    /* Fetch data */
                    $action_name = trim($protection_data[0]);
                    $max_requests = (int)trim($protection_data[1]);
                    $within_seconds = (int)trim($protection_data[2]);
                    $locking_time = (int)trim($protection_data[3]);

                    /* Validate */
                    if(strlen($action_name) > 3 && $max_requests > 0 && $within_seconds > 0 && $locking_time > 0) {
                        $protections[$action_name] = array(
                            'max_requests' => $max_requests,
                            'within_seconds' => $within_seconds,
                            'locking_time' => $locking_time
                        );
                    }
                }
            }
        }

        /* Return protections */
        return $protections;
    }

    /**
     * Add try entry and also block if required
     *
     * @param $client_ip string Ip from customer
     * @param $action string Action we are looking for
     * @param $protection array Data for protection handling
     */
    public function addEntry($client_ip, $action, $protection) {

        /**
         * Increase or add redis entry
         */
        try {

            /* Create redis client and cache key */
            $redis_client = $this->getRedisClient();
            $cache_key = $this->getCacheKey($client_ip, $action);

            /* Increase try */
            $increment = $redis_client->hIncrBy($cache_key, 'tries', 1);

            /* If this was the first try, set expiration date to within seconds and reset mail send */
            if((int)$increment === 1) {
                $redis_client->hset($cache_key, 'mail_send', 0);
                $redis_client->hset($cache_key, 'locked', 0);
                $redis_client->expire($cache_key, $protection['within_seconds']);
            }

            /* Do we reach the maximum? */
            if($increment >= $protection['max_requests']) {

                /* Is customer already locked? If not, lets lock him out */
                $locked = $redis_client->hget($cache_key, 'locked');
                if((int)$locked === 0) {
                    $redis_client->hset($cache_key, 'locked', 1);
                    $redis_client->expire($cache_key, $protection['locking_time']);
                }

                /* Check if we have to send mail */
                $mail_send = $redis_client->hget($cache_key, 'mail_send');
                if((int)$mail_send === 0) {

                    /* Send mail to config */
                    $mail_address = trim($this->scopeConfig->getValue(self::CONFIG_PATH_EMAIL));
                    if(strlen($mail_address) > 4) {
                        mail(
                            $mail_address,
                            sprintf('Blocked ip %s for action %s', (string)$client_ip, (string)$action),
                            sprintf('Blocked ip %s for action %s (key: %s)', (string)$client_ip, (string)$action, (string)$cache_key)
                        );
                    }

                    /* Mark as send */
                    $redis_client->hset($cache_key, 'mail_send', 1);
                }
            }

            /* Close connection */
            $redis_client->close();

        } catch (\Exception $e) {
            $this->_logger->error(__('Pommes Security: Can not add, increase or lock request %s', $e->getMessage()));
        }
    }

    /**
     * Check in redis if this is a blocked ip
     *
     * @param $client_ip string Ip from customer
     * @param $action string Action we are looking for
     *
     * @throws \Magento\Framework\Exception\LocalizedException
     *
     * …@return bool true if locked otherwise false
     */
    public function isLocked($client_ip, $action) {

        /**
         * Increase or add redis entry
         */
        try {

            /* Create redis client and cache key */
            $redis_client = $this->getRedisClient();
            $cache_key = $this->getCacheKey($client_ip, $action);

            /* Check if we have a lock */
            $locked = $redis_client->hget($cache_key, 'locked');
            if((int)$locked === 0 || $locked === false) {
                $locked = false;
            } else {
                $locked = true;
            }

            /* Close connection */
            $redis_client->close();

            /* Return locked */
            return $locked;

        } catch (\Exception $e) {
            $this->_logger->error(__('Pommes Security: Can not check locking state with error %s', $e->getMessage()));
        }

        return false;
    }

    private function getCacheKey($client_ip, $action) {
        return trim(strtolower($action)).md5($client_ip);
    }

    /**
     * Create a redis client using configuration
     */
    private function getRedisClient() {

        /* Fetch config data */
        $host = $this->scopeConfig->getValue(self::CONFIG_PATH_REDIS_HOST);
        $port = (int)$this->scopeConfig->getValue(self::CONFIG_PATH_REDIS_PORT);
        $database = (int)$this->scopeConfig->getValue(self::CONFIG_PATH_REDIS_DATABASE);
        $max_tries = (int)$this->scopeConfig->getValue(self::CONFIG_PATH_REDIS_MAX_CONN_TRIES);
        $timeout = (float)$this->scopeConfig->getValue(self::CONFIG_PATH_REDIS_TIMEOUT);

        /* Create redis client */
        $redis_client = new Credis_Client($host, $port, $timeout, '', $database, '');
        $redis_client->setMaxConnectRetries($max_tries);

        /* Return it */
        return $redis_client;
    }

    private function getStoreConfigAsArray ($path) {

        $config = trim($this->scopeConfig->getValue($path));
        if (!empty($config)) {
            return array_unique(array_map('trim', explode(',', $config)));
        }

        return array();
    }
}
