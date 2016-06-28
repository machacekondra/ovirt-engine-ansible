/*
Copyright (c) 2016 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package org.ovirt.ansible;

import static java.util.stream.Collectors.joining;

import java.io.File;
import java.io.IOException;
import javax.inject.Inject;

import org.ovirt.api.metamodel.concepts.Locator;
import org.ovirt.api.metamodel.concepts.Method;
import org.ovirt.api.metamodel.concepts.Model;
import org.ovirt.api.metamodel.concepts.Name;
import org.ovirt.api.metamodel.concepts.NameParser;
import org.ovirt.api.metamodel.concepts.Parameter;
import org.ovirt.api.metamodel.concepts.Service;
import org.ovirt.api.metamodel.concepts.StructType;
import org.ovirt.api.metamodel.tool.Names;
import org.ovirt.api.metamodel.tool.SchemaNames;

/**
 * This class is responsible for generating the classes that represent the ansible modules of the model.
 */
public class ModulesGenerator implements PythonGenerator {
    private static final String DOC_URL = "https://jhernand.fedorapeople.org/ovirt-api-explorer/#/types/";
    // Well known method names:
    private static final Name ADD = NameParser.parseUsingCase("Add");
    private static final Name GET = NameParser.parseUsingCase("Get");
    private static final Name LIST = NameParser.parseUsingCase("List");
    private static final Name REMOVE = NameParser.parseUsingCase("Remove");
    private static final Name UPDATE = NameParser.parseUsingCase("Update");

    // The directory were the output will be generated:
    protected File out;

    // Reference to the objects used to generate the code:
    @Inject private PythonNames pythonNames;
    @Inject private SchemaNames schemaNames;
    @Inject private Names names;

    // The buffer used to generate the code:
    private PythonBuffer buffer;

    /**
     * Set the directory were the output will be generated.
     */
    public void setOut(File newOut) {
        out = newOut;
    }

    public void generate(Model model) {
        model.services()
            .filter(
                s -> s.locators()
                    .filter(l -> l.parameters().count() > 0)
                    .findAny()
                    .isPresent()
            )
            .forEach(this::generateModule);
    }

    private Locator getServiceLocator(Service service) {
        return service.locators()
            .filter(l -> l.parameters().count() > 0)
            .findFirst()
            .orElse(null);
    }

    private void generateModule(Service service) {
        // Prepare the buffer:
        buffer = new PythonBuffer();
        buffer.setModuleName(out.getPath());
        buffer.setFileName(getModuleName(service));

        /**
         * Take service and check if it has it's locator by id.
         * If yes, fetch its methods with current service.
         */
        Locator locator = getServiceLocator(service);
        if (locator != null) {
            service.addMethods(locator.getService().getMethods());
        }

        // Generate documentation:
        generateDocumentation(service);

        // Generate the imports:
        buffer.addLine("import sys");
        buffer.addLine("import json");
        buffer.addLine();
        buffer.addLine();

        // Generate the methods:
        service.methods().sorted()
            .forEach(this::generateMethod);

        // Generate main:
        generateMain(service);

        // Write the file:
        try {
            buffer.write(out);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Error writing ansible module", exception);
        }
    }

    private void generateDocumentation(Service service) {
        buffer.addLine("DOCUMENTATION = '''");
        buffer.addLine("---");
        buffer.addLine("module: %1$s", getModuleName(service));
        buffer.addLine(
            "short_description: %1$s module to manage %2$s in oVirt", getModuleName(service), service.getName()
        );
        buffer.addLine("author: \"Ondra Machacek (@machacekondra)\"");
        buffer.addLine("version_added: 2.0");
        buffer.addLine("description:");
        buffer.startBlock();
        buffer.addLine(  "- \"This modules is used to manage oVirt %s.\"", service.getName());
        buffer.endBlock();
        buffer.addLine("options:");

        // Generate connection options documentation:
        generateConnectionDocumentation(service);

        // Generate actions documentation:
        generateParametersDocumentation(service);

        buffer.addLine("'''");
        buffer.addLine();
        buffer.addLine();

        // TODO: add RETURN
        buffer.addLine("RETURN = '''");
        buffer.addLine("'''");
        buffer.addLine();
        buffer.addLine();

        // TODO: add EXAMPLES
    }

    private void generateParametersDocumentation(Service service) {
        buffer.startBlock();
        buffer.addLine(  "service:");
        buffer.startBlock();
        buffer.addLine(    "required: false");
        buffer.addLine(    "description:");
        buffer.startBlock();
        buffer.addLine(      "- \"URL path of the service we want to work with, usually something like I(/vms/123/disks/456).\"");
        buffer.endBlock();
        buffer.endBlock();
        buffer.addLine(  "parameters:");
        buffer.startBlock();
        buffer.addLine(    "required: false");
        buffer.addLine(    "description:");
        buffer.startBlock();
        buffer.addLine(      "- \"Dictionary which specify additional parameters to be send with request.\"");

        service.methods().forEach(this::generateMethodDocumentation);

        buffer.endBlock();
        buffer.endBlock();
        buffer.endBlock();
    }

    private void generateMethodDocumentation(Method method) {
        if (method.parameters().filter(Parameter::isIn).count() == 0) {
            return;
        }

        buffer.addLine("- \" C(%s) parameters:\"", pythonNames.getMemberStyleName(method.getName()));
        method.parameters()
            .filter(Parameter::isIn)
            .forEach(
                parameter -> {
                    if (parameter.getType() instanceof StructType) {
                        buffer.addLine(
                            "- \"** I(%s)[dict] - U(%s%s).\"",
                            schemaNames.getSchemaTagName(parameter.getName()),
                            DOC_URL,
                            parameter.getName()
                        );
                    }
                    else {
                        buffer.addLine(
                            "- \"** I(%s)[%s] - %s\"",
                            schemaNames.getSchemaTagName(parameter.getName()),
                            parameter.getType().getName(),
                            parameter.getDoc() != null && parameter.getDoc().length() < 200 ? parameter.getDoc() : ""
                        );
                    }
                }
        );
    }

    private void generateConnectionDocumentation(Service service) {
        buffer.startBlock();
        buffer.addLine(  "method:");
        buffer.startBlock();
        buffer.addLine(    "required: True");
        buffer.addLine(    "description:");
        buffer.startBlock();
        buffer.addLine(      "- \"Action to be run on %s.\"", service.getName());
        buffer.endBlock();

        buffer.addLine(    "choices:");
        buffer.startBlock();
        service.methods()
            .map(m -> String.format("- %s", pythonNames.getMemberStyleName(m.getName())))
            .forEach(buffer::addLine);
        buffer.endBlock();
        buffer.endBlock();
        buffer.endBlock();

        buffer.startBlock();
        buffer.addLine(  "auth:");
        buffer.startBlock();
        buffer.addLine(    "required: True");
        buffer.addLine(    "description:");
        buffer.startBlock();
        buffer.addLine(      "- \"Dictionary with values needed to create HTTP connection to oVirt:\"");
        buffer.addLine(      "- \"** C(username)[I(required)] - The name of the user, something like `I(admin@internal)`.\"");
        buffer.addLine(      "- \"** C(password)[I(required)] - The password of the user.\"");
        buffer.addLine(      "- \"** C(url)[I(required)] - A string containing the base URL of the server, usually");
        buffer.addLine(      "something like `I(https://server.example.com/ovirt-engine/api)`.\"");
        buffer.addLine(      "- \"** C(sso_token) - SSO token to be used instead of login with username/password.\"");
        buffer.addLine(      "- \"** C(insecure) - A boolean flag that indicates if the server TLS");
        buffer.addLine(      "certificate and host name should be checked.\"");
        buffer.addLine(      "- \"** C(ca_file) - A PEM file containing the trusted CA certificates. The");
        buffer.addLine(      "certificate presented by the server will be verified using these CA");
        buffer.addLine(      "certificates. If `C(ca_file)` parameter is not set, system wide");
        buffer.addLine(      "CA certificate store is used.\"");
        buffer.endBlock();
        buffer.endBlock();
        buffer.endBlock();
    }

    private void generateMain(Service service) {
        buffer.addLine("def main():");
        buffer.startBlock();
        buffer.addLine("module = AnsibleModule(");
        buffer.startBlock();
        buffer.addLine("argument_spec=dict(");
        buffer.startBlock();
        buffer.addLine(
            "method=dict(required=True, choices=[%1$s]),",
            service.methods()
                .map(m -> String.format("'%s'", pythonNames.getMemberStyleName(m.getName())))
                .collect(joining(", "))
        );
        buffer.addLine("auth=dict(required=True, type='dict'),");
        buffer.addLine("service=dict(required=False, type='str', default=''),");
        buffer.addLine("parameters=dict(required=False, type='dict', default=dict()),");
        buffer.endBlock();
        buffer.addLine(")");
        buffer.endBlock();
        buffer.addLine(")");
        buffer.addLine();

        buffer.addLine("auth = module.params.pop('auth')");
        buffer.addLine("connection = Connection(");
        buffer.startBlock();
        buffer.addLine("url=auth.get('url'),");
        buffer.addLine("username=auth.get('username'),");
        buffer.addLine("password=auth.get('password'),");
        buffer.addLine("ca_file=auth.get('ca_file', None),");
        buffer.addLine("insecure=auth.get('insecure', False),");
        buffer.addLine("sso_token=auth.get('sso_token', None),");
        buffer.endBlock();
        buffer.addLine(")");
        buffer.addLine();

        buffer.addLine("try:");
        buffer.startBlock();
        buffer.addLine("method = module.params.pop('method')");
        buffer.addLine(
            "ret = getattr(sys.modules[__name__], method)(connection, module.params['service'], **module.params.pop('parameters'))"
        );
        buffer.addLine("module.exit_json(**ret)");
        buffer.endBlock();
        buffer.addLine("except Error as e:");
        buffer.startBlock();
        buffer.addLine(  "module.fail_json(msg=\"Error: %%s\" %% e)");
        buffer.endBlock();
        buffer.addLine("finally:");
        buffer.startBlock();
        buffer.addLine("if auth.get('sso_token', None) is None:");
        buffer.startBlock();
        buffer.addLine(  "connection.close()");
        buffer.endBlock();
        buffer.endBlock();
        buffer.endBlock();
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();

        buffer.addLine("from ansible.module_utils.basic import *");
        buffer.addLine("from ansible.module_utils.ovirt4 import *");
        buffer.addLine("if __name__ == \"__main__\":");
        buffer.startBlock();
        buffer.addLine("main()");
        buffer.endBlock();
    }

    private void generateMethod(Method method) {
        Name name = method.getName();
        if (ADD.equals(name)) {
            generateAddMethod(method);
        }
        else if (GET.equals(name)) {
            generateGetMethod(method);
        }
        else if (LIST.equals(name)) {
            generateListMethod(method);
        }
        else if (REMOVE.equals(name)) {
            generateRemoveMethod(method);
        }
        else if (UPDATE.equals(name)) {
            generateUpdateMethod(method);
        }
        else {
            generateActionMethod(method);
        }
    }

    private void generateAddMethod(Method method) {
        String tag = schemaNames.getSchemaTagName(
            names.getSingular(method.parameters().filter(Parameter::isOut).findFirst().get().getName())
        );

        // Begin method:
        Name methodName = method.getName();
        buffer.addLine("def %1$s(connection, path, **kwargs):", pythonNames.getMemberStyleName(methodName));
        // Start body:
        buffer.startBlock();

        // Body:
        buffer.addLine(
            "request = Request(method='POST', path='%%s/%s' %% path)",
            getPath(names.getPlural(getServiceLocator(method.getDeclaringService()).getName()))
        );
        buffer.addLine("request.body = json.dumps(kwargs.pop('%s'))", tag);
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("if response.code in [201, 202]:");
        buffer.startBlock();
        buffer.addLine(  "return {'changed': True, '%1$s': response.body}", tag);
        buffer.endBlock();
        buffer.addLine("return {'changed': False, 'error': response.body}");

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private void generateActionMethod(Method method) {
        // Begin method:
        String methodName = pythonNames.getMemberStyleName(method.getName());
        buffer.addLine("def %1$s(connection, path, **kwargs):", methodName);
        // Start body:
        buffer.startBlock();

        // Body:
        buffer.addLine("request = Request(method='POST', path='%%s/%s' %% path)", methodName);
        buffer.addLine("request.body = json.dumps(kwargs)");
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("if response.code in [200]:");
        buffer.startBlock();
        buffer.addLine(  "return {'changed': True}");
        buffer.endBlock();
        buffer.addLine("return {'changed': False, 'error': response.body}");

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private void generateListMethod(Method method) {
        String tag = schemaNames.getSchemaTagName(
            names.getSingular(method.parameters().filter(Parameter::isOut).findFirst().get().getName())
        );
        // Begin method:
        Name methodName = method.getName();
        buffer.addLine("def %1$s(connection, path, **kwargs):", pythonNames.getMemberStyleName(methodName));
        // Start body:
        buffer.startBlock();
        buffer.addLine(
            "request = Request(method='GET', path='%%s/%s' %% path, query=kwargs)",
            getPath(names.getPlural(getServiceLocator(method.getDeclaringService()).getName()))
        );
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("if '%s' in response.body:", tag);
        buffer.startBlock();
        buffer.addLine("return {'changed': False, '%1$s': response.body['%1$s']}", tag);
        buffer.endBlock();
        buffer.addLine("return {'changed': False, 'error': response.body}");

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private void generateGetMethod(Method method) {
        String tag = schemaNames.getSchemaTagName(
            method.parameters().filter(Parameter::isOut).findFirst().get().getName()
        );
        // Begin method:
        Name methodName = method.getName();
        buffer.addLine("def %1$s(connection, path, **kwargs):", pythonNames.getMemberStyleName(methodName));
        // Start body:
        buffer.startBlock();
        buffer.addLine("request = Request(method='GET', path='%%s' %% path, query=kwargs)");
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("return {'changed': False, '%1$s': response.body['%1$s']}", tag);

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private void generateUpdateMethod(Method method) {
        String tag = schemaNames.getSchemaTagName(
            method.parameters().filter(Parameter::isOut).findFirst().get().getName()
        );
        // Begin method:
        Name methodName = method.getName();
        buffer.addLine("def %1$s(connection, path, **kwargs):", pythonNames.getMemberStyleName(methodName));
        // Start body:
        buffer.startBlock();

        // Body:
        buffer.addLine("request = Request(method='PUT', path='%%s' %% path)");
        buffer.addLine("request.body = json.dumps(kwargs.pop('%s'))", tag);
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("if response.code in [200]:");
        buffer.startBlock();
        buffer.addLine(  "return {'changed': True, '%1$s': response.body}", tag);
        buffer.endBlock();
        buffer.addLine("return {'changed': False, 'error': response.body}");

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private void generateRemoveMethod(Method method) {
        // Begin method:
        Name methodName = method.getName();
        buffer.addLine("def %1$s(connection, path, **kwargs):", pythonNames.getMemberStyleName(methodName));
        // Start body:
        buffer.startBlock();

        // Body:
        buffer.addLine("request = Request(method='DELETE', path='%%s' %% path, query=kwargs)");
        buffer.addLine("response = connection.send(request)");
        buffer.addLine("if response.code in [200]:");
        buffer.startBlock();
        buffer.addLine(  "return {'changed': True}");
        buffer.endBlock();
        buffer.addLine("return {'changed': False, 'error': response.body}");

        // End body:
        buffer.endBlock();
        buffer.addLine();
        buffer.addLine();
    }

    private String getPath(Name name) {
        return name.words().map(String::toLowerCase).collect(joining());
    }

    /**
     * We prefix all oVirt modules with 'ov4' prefix.
     *
     * @param service service from which module is generated
     * @return prefixed name of the module
     */
    private String getModuleName(Service service) {
        return String.format(
            "ov4_%s",
            pythonNames.getMemberStyleName(service.getName())
        );
    }
}
