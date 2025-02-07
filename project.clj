(defproject org.clojars.njerig/loudmoauth "0.2.1"
  :description "A single user multi provider oauth2 client library."
  :url "http://github.com/njerig/loudmoauth"
  :license {:name "The MIT License (MIT)"
            :url "http://opensource.org/licenses/MIT"}
  :plugins [[lein-cloverage "1.0.6"]]
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [org.clojure/data.codec "0.1.0"]
                 [org.clojure/data.json "0.2.6"]
                 [clj-http "3.1.0"]
                 [prismatic/schema "1.1.2"]])
