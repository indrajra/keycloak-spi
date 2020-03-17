package org.sunbird.keycloak.core;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class SBNotification {
    private String mode = "email";
    private String deliveryType = "message";
    private Map<String, String> config = new HashMap<>();
    private Template template = new Template();
    private List<String> ids = new ArrayList<String>();

    public void addToConfig(String k, String v) {
        config.put(k, v);
    }


    public void setIds(List<String> ids) {
        this.ids = ids;
    }

    public Template getTemplate() {
        return template;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }


    public void setDeliveryType(String deliveryType) {
        this.deliveryType = deliveryType;
    }

    public void setTemplate(Template template) {
        this.template = template;
    }

    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
    public class Template {
        private String id;
        private Map<String, String> params = new HashMap<>();

        public void setId(String id) {
            this.id = id;
        }

        public void addToParams(String k, String v) {
            params.put(k, v);
        }
    }

}

