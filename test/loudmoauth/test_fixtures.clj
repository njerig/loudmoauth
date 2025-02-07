(ns loudmoauth.test-fixtures
  (:require [loudmoauth.authflow :as lma]))

(def test-state-value "34fFs29kd09")

(def test-query-param-string "client_id=5fe01282e44241328a84e7c5cc169165&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.com%2Fcallback&scope=user-read-private+user-read-email&state=34fFs29kd09") 

(def test-custom-param-query-param-string  "client_id=5fe01282e44241328a84e7c5cc169165&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.com%2Fcallback&scope=user-read-private+user-read-email&state=34fFs29kd09&show_dialog=true") 

(def test-encoded-string "SSdtIGdsYWQgSSB3b3JlIHRoZXNlIHBhbnRzLg==")

(def test-form-params-auth {:grant_type "authorization_code"
                            :code "abcdefghijklmn123456789"
                            :redirect_uri "https://www.example.com/callback" :client_id "5fe01282e44241328a84e7c5cc169165"
                            :client_secret "123456789secret"})

(def test-form-params-refresh {:grant_type "refresh_token"
                               :refresh_token "sdscgrrf343"
                               :client_id "5fe01282e44241328a84e7c5cc169165"
                               :client_secret "123456789secret"})

(def test-parsed-body {:access_token "a12dkdirnc" :refresh_token "sdscgrrf343" :expires_in 1245})

(def test-response-body-string "{\"access_token\":\"a12dkdirnc\",\"refresh_token\":\"sdscgrrf343\",\"expires_in\":1245}")

(def test-response-body-string-no-optionals "{\"access_token\":\"a12dkdirncc\"}")

(def test-token-response {:status 200 :headers {} :body test-response-body-string :request-time 0 :trace-redirects ["https://www.example.com/api/token"] :orig-content-encoding nil})   

(def test-token-response-no-optionals {:status 200 :headers {} :body test-response-body-string-no-optionals :request-time 0 :trace-redirects ["https://www.example.com/api/token"] :orig-content-encoding nil})   
(def test-query-data-auth {:form-params test-form-params-auth})

(def test-query-data-refresh {:form-params test-form-params-refresh})

(def test-code-http-response {:status 200 :headers {} :body {} :request-time 0 :trace-redirects ["https://www.example.com/api/token"] :orig-content-encoding nil :params {:state test-state-value :code "abcdefghijklmn123456789"}})

(def test-state-code-params (:params test-code-http-response))

(def auth-url (str "https://www.example.com/authorize/?" test-custom-param-query-param-string))

(def token-url "https://www.example.com/api/token") 

(def code-params {:state test-state-value :code "abcdefghijklmn123456789"})

(def new-provider-data
  {:access_token (ref nil)
   :auth-endpoint "/authorize"
   :base-url "https://www.example.com"
   :client-id "5fe01282e44241328a84e7c5cc169165"
   :client-secret "123456789secret"
   :custom-query-params {:show-dialog "true"}
   :expires_in (ref nil)
   :provider :example
   :redirect-uri "https://www.example.com/callback"
   :refresh_token (ref nil)
   :scope "user-read-private user-read-email"
   :token-endpoint "/api/token"})
 
(def new-provider-data-from-user
(dissoc new-provider-data :access_token :expires_in :refresh_token))


(def provider-data
  {:access_token (ref nil)
   :auth-endpoint "/authorize"
   :auth-url (str "https://www.example.com/authorize/?" test-custom-param-query-param-string)
   :base-url "https://www.example.com"
   :client-id "5fe01282e44241328a84e7c5cc169165"
   :client-secret "123456789secret"
   :code (promise)
   :custom-query-params {:show-dialog "true"}
   :expires_in (ref nil)
   :provider :example
   :redirect-uri "https://www.example.com/callback"
   :refresh_token (ref nil)
   :response-type "code"
   :scope "user-read-private user-read-email"
   :state test-state-value
   :token-endpoint "/api/token"
   :token-url "https://www.example.com/api/token"})

(def provider-data-with-token-response
  (merge provider-data {:token-response test-token-response}))

(def built-provider
  {:auth-url auth-url 
   :response-type  "code"
   :state test-state-value
   :token-url token-url})

(def final-provider-data
  {:access_token (ref "a12dkdirnc")
   :auth-endpoint "/authorize"
   :auth-url (str "https://www.example.com/authorize/?" test-custom-param-query-param-string)
   :base-url "https://www.example.com"
   :client-id "5fe01282e44241328a84e7c5cc169165"
   :client-secret "123456789secret"
   :code (promise)
   :custom-query-params {:show-dialog "true"}
   :expires_in (ref 1245) 
   :provider :example
   :redirect-uri "https://www.example.com/callback"
   :refresh_token (ref "sdscgrrf343")
   :response-type "code"
   :scope "user-read-private user-read-email"
   :state test-state-value
   :token-endpoint "/api/token"
   :token-response test-token-response})

(def final-provider-data-no-optionals
  (assoc (dissoc final-provider-data [:expires_in :refresh_token]) :access_token (ref (str (:access_token final-provider-data) "c"))))

(def several-providers-data
  {:example provider-data})

(def final-several-providers-data
  {:example final-provider-data})

(def final-several-providers-data-no-optionals
  {:example final-provider-data-no-optionals})

(defn reset
  "Reset the state a of our app before calling test f."
  [f]
  (f)
  (dosync
    (ref-set (:access_token provider-data) nil)  
    (ref-set (:refresh_token provider-data) nil)  
    (ref-set (:expires_in provider-data) nil)))

(defn test-uuid
  "Always return the same uuid for testin purposes."
  []
  test-state-value)

