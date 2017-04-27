/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.vmware.o11n.plugin.sdk.spring.AbstractSpringPluginAdaptor;


public final class CryptoPluginAdaptor extends  AbstractSpringPluginAdaptor{

        private static final String DEFAULT_CONFIG = "com/vmware/o11n/plugin/crypto/pluginConfig.xml";

    public static final String PLUGIN_NAME = "vRealize Orchestrator Encryption Plugin";

    static final String ROOT = "${rootElement}Finder";
    static final String REL_ROOTS = "roots";

    @Override
    protected ApplicationContext createApplicationContext(ApplicationContext defaultParent) {
        ClassPathXmlApplicationContext applicationContext = new ClassPathXmlApplicationContext(
                new String[] { DEFAULT_CONFIG }, false, defaultParent);
        applicationContext.setClassLoader(getClass().getClassLoader());
        applicationContext.refresh();

        return applicationContext;
    }
}