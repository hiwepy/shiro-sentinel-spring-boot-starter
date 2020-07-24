/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.sentinel.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.web.filter.AccessControlFilter;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.EntryType;
import com.alibaba.csp.sentinel.ResourceTypeConstants;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.Tracer;
import com.alibaba.csp.sentinel.adapter.servlet.callback.RequestOriginParser;
import com.alibaba.csp.sentinel.adapter.servlet.callback.UrlCleaner;
import com.alibaba.csp.sentinel.adapter.servlet.callback.WebCallbackManager;
import com.alibaba.csp.sentinel.adapter.servlet.config.WebServletConfig;
import com.alibaba.csp.sentinel.adapter.servlet.util.FilterUtil;
import com.alibaba.csp.sentinel.context.ContextUtil;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import com.alibaba.csp.sentinel.util.StringUtil;

/**
 * Access Control Filter that integrates with Sentinel.
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 * @see {@link com.alibaba.csp.sentinel.adapter.servlet.CommonFilter}
 */
public class CommonFilter extends AccessControlFilter {

	 /**
     * Specify whether the URL resource name should contain the HTTP method prefix (e.g. {@code POST:}).
     */
    public static final String HTTP_METHOD_SPECIFY = "HTTP_METHOD_SPECIFY";
    /**
     * If enabled, use the default context name, or else use the URL path as the context name,
     * {@link WebServletConfig#WEB_SERVLET_CONTEXT_NAME}. Please pay attention to the number of context (EntranceNode),
     * which may affect the memory footprint.
     *
     * @since 1.7.0
     */
    public static final String WEB_CONTEXT_UNIFY = "WEB_CONTEXT_UNIFY";

    private final static String COLON = ":";
    
    private static final String EMPTY_ORIGIN = "";

    private boolean httpMethodSpecify = false;
    private boolean webContextUnify = true;
	
	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		HttpServletRequest sRequest = WebUtils.toHttp(request);
        Entry urlEntry = null;

        try {
            String target = FilterUtil.filterTarget(sRequest);
            // Clean and unify the URL.
            // For REST APIs, you have to clean the URL (e.g. `/foo/1` and `/foo/2` -> `/foo/:id`), or
            // the amount of context and resources will exceed the threshold.
            UrlCleaner urlCleaner = WebCallbackManager.getUrlCleaner();
            if (urlCleaner != null) {
                target = urlCleaner.clean(target);
            }

            // If you intend to exclude some URLs, you can convert the URLs to the empty string ""
            // in the UrlCleaner implementation.
            if (!StringUtil.isEmpty(target)) {
                // Parse the request origin using registered origin parser.
                String origin = parseOrigin(sRequest);
                String contextName = webContextUnify ? WebServletConfig.WEB_SERVLET_CONTEXT_NAME : target;
                ContextUtil.enter(contextName, origin);

                if (httpMethodSpecify) {
                    // Add HTTP method prefix if necessary.
                    String pathWithHttpMethod = sRequest.getMethod().toUpperCase() + COLON + target;
                    urlEntry = SphU.entry(pathWithHttpMethod, ResourceTypeConstants.COMMON_WEB, EntryType.IN);
                } else {
                    urlEntry = SphU.entry(target, ResourceTypeConstants.COMMON_WEB, EntryType.IN);
                }
            }
            chain.doFilter(request, response);
        } catch (BlockException e) {
            HttpServletResponse sResponse = (HttpServletResponse) response;
            // Return the block page, or redirect to another URL.
            WebCallbackManager.getUrlBlockHandler().blocked(sRequest, sResponse, e);
        } catch (IOException | ServletException | RuntimeException e2) {
            Tracer.traceEntry(e2, urlEntry);
            throw e2;
        } finally {
            if (urlEntry != null) {
                urlEntry.exit();
            }
            ContextUtil.exit();
        }
		
	}

    private String parseOrigin(HttpServletRequest request) {
        RequestOriginParser originParser = WebCallbackManager.getRequestOriginParser();
        String origin = EMPTY_ORIGIN;
        if (originParser != null) {
            origin = originParser.parseOrigin(request);
            if (StringUtil.isEmpty(origin)) {
                return EMPTY_ORIGIN;
            }
        }
        return origin;
    }
    
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return true;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}

	public boolean isHttpMethodSpecify() {
		return httpMethodSpecify;
	}

	public void setHttpMethodSpecify(boolean httpMethodSpecify) {
		this.httpMethodSpecify = httpMethodSpecify;
	}

	public boolean isWebContextUnify() {
		return webContextUnify;
	}

	public void setWebContextUnify(boolean webContextUnify) {
		this.webContextUnify = webContextUnify;
	}
	
}
