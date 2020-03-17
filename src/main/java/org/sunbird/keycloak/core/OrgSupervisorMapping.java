package org.sunbird.keycloak.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class OrgSupervisorMapping {
    private static Logger logger = Logger.getLogger(OrgSupervisorMapping.class);
    private JsonNode orgSupervisorMap;

    public OrgSupervisorMapping() throws IOException {
        try {
            orgSupervisorMap = new ObjectMapper().readTree(readMapping());
            logger.info(orgSupervisorMap.toString());

        } catch (IOException e) {
            logger.error("Error loading org supervisor mapping"  + e);
            throw e;
        }
    }

    public JsonNode getOrgSupervisorMap() {
        return orgSupervisorMap;
    }

    private String readMapping() throws IOException {
            InputStream inputStream = OrgSupervisorMapping.class.getResourceAsStream("/OrgSupervisorMap.json");
            InputStreamReader isReader = new InputStreamReader(inputStream);
            BufferedReader reader = new BufferedReader(isReader);
            StringBuffer sb = new StringBuffer();
            String str;
            while((str = reader.readLine())!= null){
                sb.append(str);
            }
            return sb.toString();
    }

}
