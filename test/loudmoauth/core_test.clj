(ns loudmoauth.core-test
  (:require [clojure.test :refer :all]
            [loudmoauth.core :refer :all]
            [loudmoauth.test-fixtures :as tf]
            [loudmoauth.util :as lmutil]
            [loudmoauth.authflow :as lma]
            [loudmoauth.provider :as p]
            [clojure.core.async :as a]))

(deftest test-parse-params
  (testing "Test parsing of :code and :state in incoming request params."
    (deliver (:code (tf/test-state-value-keyword tf/final-several-providers-data)) "abcdefghijklmn123456789")
    (with-redefs [lma/providers (atom tf/final-several-providers-data)]  
      (parse-params tf/test-code-http-response)
      (is (= @(:code tf/final-provider-data) @(:code (p/provider-reverse-lookup :example @lma/providers)))))))

(deftest test-refresh-token
  (testing "Test refresh of tokens. This is basically two call to get tokens but with one instance of provider-data where refresh_token is already present and second where it is not."
 (with-redefs [lma/http-post-for-tokens (fn [provider-data] tf/test-token-response)
               lma/providers (atom tf/final-several-providers-data)]
   (refresh-token :example)
   (is (= @(:access_token tf/final-provider-data) (oauth-token :example))))))

(deftest test-user-interaction
  (testing "Pull the url used for interaction from channel and publish on end point where hopefully browser is waiting. In the first test we have something on the channel, in the second one the channel is empty."
    (tf/reset-channels)
    (a/go (a/>! lma/interaction-chan (:auth-url tf/final-provider-data)))
    (Thread/sleep 2000)
    (is (= (:auth-url tf/final-provider-data) (user-interaction))) 
    (is (= nil (user-interaction)))))

(deftest test-delete-provider
  (testing "Remove provider from providers"
    (with-redefs [lma/providers (atom tf/final-several-providers-data)]
      (delete-provider :example)  
      (is (= {} @lma/providers)))))

(deftest test-oauth-token
  (testing "Retrieve oauth-token from state-map."
    ( with-redefs [lma/providers (atom tf/final-several-providers-data)]  
      (is (= @(:access_token tf/final-provider-data) (oauth-token :example))))))
