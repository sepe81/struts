/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.struts2.dispatcher;

import com.opensymphony.xwork2.ActionContext;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Contains initialization operations
 */
public class InitOperations {

    public InitOperations() {
    }

    /**
     * Creates and initializes the dispatcher
     *
     * @param filterConfig host configuration
     * @return the dispatcher
     */
    public Dispatcher initDispatcher(HostConfig filterConfig) {
        Dispatcher dispatcher = createDispatcher(filterConfig);
        dispatcher.init();
        return dispatcher;
    }

    /**
     * Initializes the static content loader with the filter configuration
     *
     * @param filterConfig host configuration
     * @param dispatcher   the dispatcher
     * @return the static content loader
     */
    public StaticContentLoader initStaticContentLoader(HostConfig filterConfig, Dispatcher dispatcher) {
        StaticContentLoader loader = dispatcher.getStaticContentLoader();
        loader.setHostConfig(filterConfig);
        return loader;
    }

    /**
     * @return The dispatcher on the thread.
     * @throws IllegalStateException If there is no dispatcher available
     */
    public Dispatcher findDispatcherOnThread() {
        Dispatcher dispatcher = Dispatcher.getInstance();
        if (dispatcher == null) {
            throw new IllegalStateException("Must have the StrutsPrepareFilter execute before this one");
        }
        return dispatcher;
    }

    /**
     * Create a {@link Dispatcher}
     *
     * @param filterConfig host configuration
     * @return The dispatcher on the thread.
     */
    protected Dispatcher createDispatcher(HostConfig filterConfig) {
        Map<String, String> params = new HashMap<>();
        for (Iterator<String> parameterNames = filterConfig.getInitParameterNames(); parameterNames.hasNext(); ) {
            String name = parameterNames.next();
            String value = filterConfig.getInitParameter(name);
            params.put(name, value);
        }
        return new Dispatcher(filterConfig.getServletContext(), params);
    }

    public void cleanup() {
        ActionContext.clear();
    }

    /**
     * Extract a list of patterns to exclude from request filtering
     *
     * @param dispatcher The dispatcher to check for exclude pattern configuration
     * @return a List of Patterns for request to exclude if apply, or <tt>null</tt>
     * @see org.apache.struts2.StrutsConstants#STRUTS_ACTION_EXCLUDE_PATTERN
     * @deprecated since 6.4.0, use {@link Dispatcher#getActionExcludedPatterns()} instead.
     */
    @Deprecated
    public List<Pattern> buildExcludedPatternsList(Dispatcher dispatcher) {
        return dispatcher.getActionExcludedPatterns();
    }

}
