/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import com.vmware.o11n.plugin.sdk.module.ModuleBuilder;

public final class CryptoModuleBuilder extends ModuleBuilder {

    private static final String DESCRIPTION = "vRealize Orchestrator Encryption Plugin";

    private static final String DATASOURCE = "main-datasource";

    @Override
    public void configure() {
        module("Crypto").withDescription(DESCRIPTION).withImage("images/default-16x16.png")
                .basePackages(CryptoModuleBuilder.class.getPackage().getName()).version(
                "${project.version}");

        installation(InstallationMode.BUILD).action(ActionType.INSTALL_PACKAGE,
                "packages/${project.artifactId}-package-${project.version}.package");

        finderDatasource(CryptoPluginAdaptor.class, DATASOURCE).anonymousLogin(LoginMode.INTERNAL);
    }
}
