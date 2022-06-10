(ns loudmoauth.core
  (:require [loudmoauth.authflow :as lma]
            [loudmoauth.provider :as p])) 

(defn parse-params
  "Parse parameters in URL from the OAuth 2 server HTTP response."
  [response]
  (->> response 
       :params
       (lma/match-code-to-provider)))

;Reverser match on provider name instead of state
(defn refresh-token
  "In case the token refresher doesn't work, call this function with provider keyword to update
  a specific provider, calling it without arguments tries to update all keys."
  ([provider]
   (let [provider-data (provider @lma/providers)]
     (if @(:refresh_token provider-data)
       (->> (lma/get-tokens provider-data)
            (lma/add-to-providers))
       (->> (merge provider-data {:code (promise)})
            (lma/init-and-add-provider)))))) 

(defn user-interaction
  "Returns user interaction url if present, nil if not."
  []
  (when-let [auth-url (:auth-url (some #(if-not @(:access_token %) %) (vals @lma/providers)))]
    auth-url))

(defn add-provider
  "Adds provider based on user provided provider-data map and initiates chain
  of function calls to retrieve an oauth token."
  [provider-params]
    (lma/init-and-add-provider (p/create-new-provider provider-params)))

(defn logout-provider
  "Removes token data from provider and changes state."
  [provider]
  (let [provider-data (provider @lma/providers)
        provider-data-sans-tokens (merge provider-data (p/build-provider provider-data))]
    (lma/init-and-add-provider provider-data-sans-tokens)))

;What if we delete a provider that's in the middle of updating?
(defn delete-provider
  "Remove provider and token data."
  [provider]
  (swap! lma/providers dissoc provider))

(defn oauth-token
  "Retrieve oauth token for use in authentication call. Returns nil if the 
  authentication process hasn't started."
  [provider]
  (let [provider-data (provider @lma/providers)]
    (if-let [access-token-ref (:access_token provider-data)]
      @access-token-ref
      nil)))
