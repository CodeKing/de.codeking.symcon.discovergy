<?php

define('__ROOT__', dirname(dirname(__FILE__)));
require_once(__ROOT__ . '/libs/helpers/autoload.php');

/**
 * Class Discovergy
 * Driver to Discovergy API
 *
 * @version     1.2
 * @category    Symcon
 * @package     de.codeking.symcon.discovergy
 * @author      Frank Herrmann <frank@codeking.de>
 * @link        https://codeking.de
 * @link        https://github.com/CodeKing/de.codeking.symcon.discovergy
 *
 */
class Discovergy extends Module
{
    use InstanceHelper;

    const api = 'https://api.discovergy.com/public/v1';

    private $email;
    private $password;
    private $consumer_token;
    private $consumer_secret;
    private $oauth_token;
    private $oauth_secret;
    private $oauth_verifier;
    private $meters = [];

    private $renew_token = false;

    private $ch;

    public $data = [];
    private $position_offset = 0;

    protected $archive_mappings = [ // archive: 0 = default, 1 = counter
        'Power' => 0,
        'Meter Reading' => 1,
        'Feed-In' => 1
    ];

    protected $profile_mappings = [
        'Serial' => '~String',
        'Meter ID' => '~String',
        'Type' => '~String',
        'Measurement Type' => '~String',
        'Meter Reading' => 'kWh',
        'Feed-In' => 'kWh',
        'Power' => 'Watt',
        'Power L1' => 'Watt',
        'Power L2' => 'Watt',
        'Power L3' => 'Watt',
        'Volume' => '~Gas'
    ];

    /**
     * destruction
     */
    public function __destruct()
    {
        // close curl handle, if available
        if ($this->ch) {
            curl_close($this->ch);
        }
    }

    /**
     * create instance
     * @return bool|void
     */
    public function Create()
    {
        parent::Create();

        // register public properties
        $this->RegisterPropertyString('email', 'user@email.com');
        $this->RegisterPropertyString('password', '');
        $this->RegisterPropertyInteger('interval', 60); // in seconds

        // register timer
        $this->RegisterTimer('UpdateData', 60 * 1000, $this->_getPrefix() . '_Update($_IPS[\'TARGET\']);');
    }

    /**
     * execute, when kernel is ready
     */
    protected function onKernelReady()
    {
        // check configuration data
        $validConfig = $this->ReadConfig();

        // update timer
        if ($validConfig) {
            $this->SetTimerInterval('UpdateData', $this->ReadPropertyInteger('interval') * 1000);
        }
    }

    /**
     * Read config
     * @return bool
     */
    private function ReadConfig()
    {
        // get settings
        $this->email = $this->ReadPropertyString('email');
        $this->password = $this->ReadPropertyString('password');

        $this->oauth_token = $this->GetBuffer('oauth_token');
        $this->oauth_secret = $this->GetBuffer('oauth_secret');
        $this->consumer_token = $this->GetBuffer('consumer_token');
        $this->consumer_secret = $this->GetBuffer('consumer_secret');
        if ($this->meters = $this->GetBuffer('meters')) {
            $this->meters = json_decode($this->meters, true);
        }

        // return if service or internet connection is not available
        if (!Sys_Ping('api.discovergy.com', 1000)) {
            $this->_log('Discovergy', 'Error: api or internet connection not available!');
            exit(-1);
        }

        // check if email and password are provided
        if (!$this->email || !$this->password) {
            return false;
        }

        // try to login if no valid token was provided
        if (!$this->oauth_token) {
            return $this->Login();
        }

        // config seems to be valid, return true :-)
        $this->SetStatus(102);
        return true;
    }

    /**
     * read & update meter data
     */
    public function UpdateMeter()
    {
        // read config
        if (!$this->ReadConfig()) {
            return false;
        };

        // get all meters
        if ($meters = $this->Api('meters')) {
            $this->meters = [];
            foreach ($meters AS $meter) {
                $this->meters[$meter['type'] . '_' . $meter['serialNumber']] = $meter['measurementType'];
                $this->data[] = [
                    'Serial' => $meter['serialNumber'],
                    'Meter ID' => $meter['administrationNumber'],
                    'Type' => $meter['type'],
                    'Measurement Type' => $meter['measurementType']
                ];
            }
        }

        // save meters to buffer
        $this->SetBuffer('meters', json_encode($this->meters));

        // log data
        $this->_log('Discovergy Meters', json_encode($this->data));

        // save meters
        $this->position_offset = 0;
        $this->SaveMeters();

        return true;
    }

    /**
     * read & update consumption data
     */
    public function Update()
    {
        // read config
        if (!$this->ReadConfig()) {
            return false;
        };

        // update meters, if empty
        if (!$this->meters) {
            $this->UpdateMeter();
        }

        // loop meters and get current data
        foreach ($this->meters AS $meter_id => $measurement_type) {
            if ($meter = $this->Api('last_reading', [
                'meterId' => $meter_id
            ])) {
                // get values
                $values = $meter['values'];

                // append data by type
                switch ($measurement_type):
                    case 'ELECTRICITY':
                        $this->_log('Discovergy Values', json_encode($values));

                        $this->data[$meter_id] = [
                            'Meter Reading' => $values['energy'] / 10000000000
                        ];

                        if (isset($values['energyOut'])) {
                            $this->data[$meter_id]['Feed-In'] = $values['energyOut'] / 10000000000;
                        }

                        $this->data[$meter_id]['Power'] = $values['power'] / 1000;

                        if (isset($values['power1'])) {
                            $this->data[$meter_id]['Power L1'] = $values['power1'] / 1000;
                        }

                        if (isset($values['power2'])) {
                            $this->data[$meter_id]['Power L2'] = $values['power2'] / 1000;
                        }

                        if (isset($values['power3'])) {
                            $this->data[$meter_id]['Power L3'] = $values['power3'] / 1000;
                        }
                        break;
                    case 'GAS':
                        $this->_log('Discovergy Values', json_encode($values));

                        $this->data[$meter_id] = [
                            'Volume' => $values['volume'] / 1000
                        ];
                        break;
                endswitch;
            }
        }

        // log data
        $this->_log('Discovergy Meters', json_encode($this->data));

        // save meters
        $this->position_offset = 10;
        $this->SaveData();

        return true;
    }

    /**
     * save meters
     */
    private function SaveMeters()
    {
        // loop meters and save data
        foreach ($this->data AS $data) {
            $meter_id = $data['Type'] . '_' . $data['Serial'];

            // get category id from meter id
            $category_id_meter = $this->CreateCategoryByIdentifier($this->InstanceID, $meter_id, $data['Meter ID']);

            // loop meter data and add variables to category
            $position = $this->position_offset;
            foreach ($data AS $key => $value) {
                $this->CreateVariableByIdentifier([
                    'parent_id' => $category_id_meter,
                    'name' => $key,
                    'value' => $value,
                    'position' => $position
                ]);
                $position++;
            }
        }

        // reset data
        $this->data = [];
    }

    /**
     * save data to variables
     */
    private function SaveData()
    {
        // loop data and save to variable
        $position = $this->position_offset;
        foreach ($this->data AS $meter_id => $data) {
            // get category id from meter id
            $category_id_meter = $this->CreateCategoryByIdentifier($this->InstanceID, $meter_id);

            foreach ($data AS $key => $value) {
                $this->CreateVariableByIdentifier([
                    'parent_id' => $category_id_meter,
                    'name' => $key,
                    'value' => $value,
                    'position' => $position
                ]);
                $position++;
            }
        }

        // reset data
        $this->data = [];
    }

    /**
     * Login to Discovergy
     */
    public function Login()
    {
        $this->_log('Discovergy', sprintf('Logging in to account of %s...', $this->email));

        // unset current tokens
        $this->oauth_token = NULL;
        $this->oauth_secret = NULL;
        $this->oauth_verifier = NULL;

        // register application
        $this->RegisterApplication();

        // get request token
        $this->GetRequestToken();

        // authorize request token
        $this->AuthorizeToken();

        // get access token
        $this->GetAccessToken();

        // check login
        if (!$meters = $this->Api('meters')) {
            $this->oauth_token = NULL;
            $this->oauth_secret = NULL;
        }

        // save valid token
        if ($this->oauth_token && $this->oauth_secret) {
            $this->meters = [];
            foreach ($meters AS $meter) {
                $this->meters[$meter['type'] . '_' . $meter['serialNumber']] = $meter['measurementType'];
            }

            $this->SetBuffer('consumer_token', $this->consumer_token);
            $this->SetBuffer('consumer_secret', $this->consumer_secret);
            $this->SetBuffer('oauth_token', $this->oauth_token);
            $this->SetBuffer('oauth_secret', $this->oauth_secret);
            $this->SetBuffer('meters', json_encode($this->meters));
        } else {
            $this->SetStatus(201);
            exit(-1);
        }

        return true;
    }

    /**
     * basic oauth api
     * @param string $endpoint
     * @param array $params
     * @return mixed
     */
    private function Api(string $endpoint, $params = [])
    {
        // build uri
        $uri = self::api . '/' . $endpoint;

        // get method by uri
        $method = basename($uri);

        // set default curl options
        $curlOptions = [
            CURLOPT_HEADER => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => NULL,
            CURLOPT_HTTPHEADER => [],
            CURLOPT_CUSTOMREQUEST => 'GET'
        ];

        // set options by method
        switch ($method):
            case 'consumer_token':
                $curlOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
                $curlOptions[CURLOPT_POSTFIELDS] = http_build_query(['client' => 'IP-Symcon']);
                $curlOptions[CURLOPT_HTTPHEADER] = [
                    'Content-Type: application/x-www-form-urlencoded'
                ];
                break;
            case 'request_token':
                $curlOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
                $curlOptions[CURLOPT_HTTPHEADER] = [
                    $this->_buildAuthorizationHeader('POST', $uri)
                ];
                break;
            case 'authorize':
                $params = [
                    'oauth_token' => $this->oauth_token,
                    'email' => $this->email,
                    'password' => $this->password
                ];

                $uri .= '?' . http_build_query($params);
                break;
            case 'access_token':
                $curlOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
                $curlOptions[CURLOPT_HTTPHEADER] = [
                    $this->_buildAuthorizationHeader('POST', $uri)
                ];

                $uri .= '';
                break;
            default:
                if ($params) {
                    $uri .= '?' . http_build_query($params);
                }

                $curlOptions[CURLOPT_HTTPHEADER] = [
                    $this->_buildAuthorizationHeader('GET', $uri)
                ];
                break;
        endswitch;

        // init curl or set new uri
        if ($this->ch) {
            curl_setopt($this->ch, CURLOPT_URL, $uri);
        } else {
            $this->ch = curl_init($uri);
        }

        // set curl options
        curl_setopt_array($this->ch, $curlOptions);

        // exec curl
        $result = curl_exec($this->ch);
        $status = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);

        // return false on invalid http code
        if ($status != 200) {
            // try to renew token on unauthorized response
            if ($status == 401 && !$this->renew_token) {
                $this->renew_token = true;
                if ($this->Login()) {
                    return $this->Api($endpoint, $params);
                }
            }

            // error handling
            if ($status == 403) {
                $this->SetStatus(201);
            } else {
                $this->SetStatus(202);
            }

            // return false :(
            return false;
        }

        // try to convert json to array
        $json = json_decode($result, true);
        if (json_last_error() == JSON_ERROR_NONE) {
            $result = $json;
        } // otherwise, convert query to array
        else {
            parse_str($result, $result);
        }

        // return result
        return $result;
    }

    /**
     * Register Module as application
     * @return bool
     */
    private function RegisterApplication()
    {
        // get consumer token
        $endpoint = 'oauth1/consumer_token';

        // get consumer data
        if ($data = $this->Api($endpoint)) {
            // set tokens
            $this->consumer_token = isset($data['key']) ? $data['key'] : false;
            $this->consumer_secret = isset($data['secret']) ? $data['secret'] : false;

            // return bool, if consumer token was set
            return !($this->consumer_token);
        }

        // fallback: return false
        return false;
    }

    /**
     * get request token
     * @return bool
     */
    private function GetRequestToken()
    {
        if (!$this->consumer_token || !$this->consumer_secret) {
            return false;
        }

        // get request token
        $endpoint = 'oauth1/request_token';

        // get request token data
        if ($data = $this->Api($endpoint)) {
            // set tokens
            $this->oauth_token = isset($data['oauth_token']) ? $data['oauth_token'] : false;
            $this->oauth_secret = isset($data['oauth_token_secret']) ? $data['oauth_token_secret'] : false;

            // return bool, if consumer request token was set
            return !($this->oauth_token);
        }

        // fallback: return false
        return false;
    }

    /**
     * authorize token
     * @return bool
     */
    private function AuthorizeToken()
    {
        if (!$this->oauth_token || !$this->oauth_secret) {
            return false;
        }

        // authorize token
        $endpoint = 'oauth1/authorize';

        // get verifier data
        if ($data = $this->Api($endpoint)) {
            // set verifier
            $this->oauth_verifier = isset($data['oauth_verifier']) ? $data['oauth_verifier'] : false;

            // return bool, if token was authorized
            return !($this->oauth_verifier);
        }

        // fallback: return false
        return false;
    }

    /**
     * get access token
     * @return bool
     */
    private function GetAccessToken()
    {
        if (!$this->oauth_verifier) {
            return false;
        }

        // authorize token
        $endpoint = 'oauth1/access_token';

        // get access token data
        if ($data = $this->Api($endpoint)) {
            // set tokens
            $this->oauth_token = isset($data['oauth_token']) ? $data['oauth_token'] : false;
            $this->oauth_secret = isset($data['oauth_token_secret']) ? $data['oauth_token_secret'] : false;

            // return bool, if access token was set
            return !($this->oauth_token);
        };

        // fallback: return false
        return false;
    }

    /**
     * build uri base string
     * @param string $baseURI
     * @param string $method
     * @param array $params
     * @return string
     */
    private function _buildBaseString(string $baseURI = NULL, $method = 'GET', array $params = [])
    {
        $url = parse_url($baseURI);
        if (isset($url['query'])) {
            parse_str($url['query'], $params2);
            $params = array_merge($params, $params2);
        }

        $baseURI = $url['scheme'] . '://' . $url['host'] . $url['path'];

        $r = [];
        ksort($params);
        foreach ($params AS $consumer_key => $value) {
            $r[] = "$consumer_key=" . rawurlencode($value);
        }
        return $method . '&' . rawurlencode($baseURI) . '&' . rawurlencode(implode('&', $r));
    }

    /**
     * build oAuth header
     * @param string $request
     * @param string $uri
     * @return string
     */
    private function _buildAuthorizationHeader($request = 'GET', string $uri = '')
    {
        // get method by uri
        $method = basename($uri);

        // default oauth data
        $oauthData = [
            'oauth_consumer_key' => $this->consumer_token,
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_nonce' => md5(mt_rand()),
            'oauth_version' => '1.0'
        ];

        // append token, if available
        if ($this->oauth_token) {
            $oauthData['oauth_token'] = $this->oauth_token;
        }

        // append verifier on getting access token
        if ($method == 'access_token') {
            $oauthData['oauth_verifier'] = $this->oauth_verifier;
        }

        // build signature
        $base_string = $this->_buildBaseString($uri, $request, $oauthData);
        $consumer_key = rawurlencode($this->consumer_secret) . '&' . rawurlencode($this->oauth_secret);
        $signature = base64_encode(hash_hmac('sha1', $base_string, $consumer_key, true));

        // append signature
        $oauthData['oauth_signature'] = $signature;

        // build authorization header
        $header = 'Authorization: OAuth ';
        $values = [];
        foreach ($oauthData AS $key => $value) {
            $values[] = "$key=\"" . rawurlencode($value) . "\"";
        }

        $header .= implode(",", $values);

        return $header;
    }


    /**
     * create custom variable profile
     * @param string $profile_id
     * @param string $name
     */
    protected function CreateCustomVariableProfile(string $profile_id, string $name)
    {
        switch ($name):
            case 'Watt':
                IPS_CreateVariableProfile($profile_id, 2); // float
                IPS_SetVariableProfileDigits($profile_id, 0); // 0 decimals
                IPS_SetVariableProfileText($profile_id, '', ' W'); // Watt
                IPS_SetVariableProfileIcon($profile_id, 'Electricity');
                break;
            case 'kWh':
                IPS_CreateVariableProfile($profile_id, 2); // float
                IPS_SetVariableProfileDigits($profile_id, 2); // 2 decimals
                IPS_SetVariableProfileText($profile_id, '', ' kWh'); // Watt
                IPS_SetVariableProfileIcon($profile_id, 'Electricity');
                break;
            case 'Price':
                IPS_CreateVariableProfile($profile_id, 2); // float
                IPS_SetVariableProfileDigits($profile_id, 4); // 4 decimals
                IPS_SetVariableProfileText($profile_id, '', ' €'); // currency symbol
                IPS_SetVariableProfileIcon($profile_id, 'Euro');
                break;
        endswitch;
    }
}