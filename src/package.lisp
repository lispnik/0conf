;;;; package.lisp

(defpackage #:0conf
  (:use #:cl)
  (:nicknames #:zeroconf)
  (:export
   ;; constants
   #:+class-in+ #:+cache-flush-bit+
   #:+type-a+ #:+type-ns+ #:+type-cname+ #:+type-ptr+ #:+type-txt+
   #:+type-aaaa+ #:+type-srv+ #:+type-nsec+ #:+type-any+
   #:+mdns-port+ #:+mdns-group-v4+ #:+mdns-group-v6+ #:+flag-response+
   ;; octet codec
   #:make-writer #:writer-result #:writer-position #:writer-bytes
   #:write-u8 #:write-u16 #:write-u32 #:write-octets #:write-name
   #:make-reader #:reader-pos #:read-u8 #:read-u16 #:read-u32 #:read-octets #:read-name
   #:parse-ipv4 #:format-ipv4 #:parse-ipv6 #:format-ipv6
   ;; records
   #:resource-record #:rr-name #:rr-type #:rr-class #:rr-cache-flush #:rr-ttl
   #:a-record #:a-address
   #:aaaa-record #:aaaa-address
   #:ptr-record #:ptr-target
   #:srv-record #:srv-priority #:srv-weight #:srv-port #:srv-target
   #:txt-record #:txt-strings
   #:nsec-record #:nsec-next-name #:nsec-types
   #:unknown-record #:rr-rdata
   #:write-record #:read-record #:write-rdata
   ;; message
   #:dns-message #:make-dns-message
   #:dns-message-id #:dns-message-flags
   #:dns-message-questions #:dns-message-answers
   #:dns-message-authorities #:dns-message-additionals
   #:question #:make-question
   #:question-name #:question-qtype #:question-qclass #:question-unicast-response
   #:encode-message #:decode-message
   ;; cache
   #:cache #:make-cache #:cache-add #:cache-get #:cache-all #:cache-expire
   #:cache-entry #:cache-entry-record #:cache-entry-expires
   ;; service-info / DNS-SD
   #:service-info #:make-service-info
   #:service-info-type #:service-info-name #:service-info-host #:service-info-port
   #:service-info-addresses #:service-info-txt
   #:service-info-priority #:service-info-weight
   #:service-instance-name #:service-info-records #:service-info-from-records
   #:txt-alist->strings #:txt-strings->alist
   ;; transport
   #:mdns-socket #:make-mdns-socket #:mdns-send #:mdns-recv #:close-mdns-socket
   ;; responder / browser / public API
   #:responder #:make-responder #:start-responder #:stop-responder
   #:register-service #:unregister-service
   #:browse #:browse-once
   #:service-browser #:browse-services #:stop-browse
   #:start #:stop))
