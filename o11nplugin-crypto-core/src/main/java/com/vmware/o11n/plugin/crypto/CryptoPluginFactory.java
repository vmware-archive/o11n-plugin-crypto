/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import java.util.List;

import com.vmware.o11n.plugin.sdk.spring.AbstractSpringPluginFactory;
import com.vmware.o11n.plugin.sdk.spring.InventoryRef;

import ch.dunes.vso.sdk.api.QueryResult;

public final class CryptoPluginFactory extends AbstractSpringPluginFactory {

    @Override
    public Object find(InventoryRef ref) {
        throw new UnsupportedOperationException("implement me");
    }

    @Override
    public QueryResult findAll(String type, String query) {
        throw new UnsupportedOperationException("implement me");
    }

    @Override
    public List<?> findChildrenInRootRelation(String type, String relationName) {
        throw new UnsupportedOperationException("implement me");
    }

    @Override
    public List<?> findChildrenInRelation(InventoryRef parent, String relationName) {
        throw new UnsupportedOperationException("implement me");
    }
}