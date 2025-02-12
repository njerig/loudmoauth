(ns loudmoauth.core-test
  (:require [clojure.test :refer :all]
            [loudmoauth.core :refer :all]
            [loudmoauth.test-fixtures :as tf]
            [loudmoauth.util :as lmutil]
            [loudmoauth.authflow :as lma]
            [loudmoauth.provider :as p]))

(use-fixtures :each tf/reset)

(deftest test-parse-params
  (testing "Test parsing of :code and :state in incoming request params."
    (with-redefs [lma/providers (atom tf/final-several-providers-data)]  
      (deliver (:code (:example tf/final-several-providers-data)) "abcdefghijklmn123456789")
      (parse-params tf/test-code-http-response)
      (is (= @(:code tf/final-provider-data) @(:code (p/provider-reverse-lookup :example @lma/providers)))))))

;TODO - fix the "c" below
(deftest test-refresh-token
  (testing "Test refresh of tokens. This is basically two call to get tokens but with one instance of provider-data where refresh_token is already present and second where it is not."
    (with-redefs [lma/http-post-for-tokens (fn [provider-data] tf/test-token-response)
                  lma/providers (atom tf/final-several-providers-data)]
      (refresh-token :example)
      (is (= @(:access_token tf/final-provider-data) (oauth-token :example))))

    (with-redefs [lma/http-post-for-tokens (fn [provider-data] tf/test-token-response-no-optionals)
                  lma/providers (atom tf/final-several-providers-data-no-optionals)]
      (refresh-token :example)
      (is (= (str  @(:access_token tf/final-provider-data) "c") (oauth-token :example))))) )

(deftest test-user-interaction
  (testing "Pull the url used for interaction from channel and publish on end point where hopefully browser is waiting. In the first test we have something on the channel, in the second one the channel is empty."
(with-redefs [lma/providers (atom tf/several-providers-data)]
    (is (= (:auth-url tf/provider-data) (user-interaction))))))

(deftest test-delete-provider
  (testing "Remove provider from providers"
    (with-redefs [lma/providers (atom tf/final-several-providers-data)]
      (delete-provider :example)  
      (is (= {} @lma/providers)))))

(deftest test-oauth-token
  (testing "Retrieve oauth-token from state-map."
    ( with-redefs [lma/providers (atom tf/final-several-providers-data)]  
      (is (= @(:access_token tf/final-provider-data) (oauth-token :example))))))
