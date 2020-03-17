package org.sunbird.keycloak.core;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class SBNotificationPayload {
    private String id = "notification.message.send";
    private String ver = "1.0";
    private String ets = "";
    private Params params = new Params();
    private Request request = new Request();

    public SBNotificationPayload() {}

    public void setRequest(List<SBNotification> notification) {
        this.request.notifications = notification;
    }

    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
    public class Params {
        private String did;
        private String key;
        private String msgid;
    }

    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
    public class Request {
        private List<SBNotification> notifications = new ArrayList<SBNotification>();
    }

    @Override
    public java.lang.String toString() {
        ObjectMapper Obj = new ObjectMapper();
        String jsonStr = null;
        try {
            jsonStr = Obj.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return jsonStr;
    }
}
