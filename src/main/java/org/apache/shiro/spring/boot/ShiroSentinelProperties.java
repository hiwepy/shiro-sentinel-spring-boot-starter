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
package org.apache.shiro.spring.boot;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.alibaba.csp.sentinel.slots.block.authority.AuthorityRule;
import com.alibaba.csp.sentinel.slots.block.degrade.DegradeRule;
import com.alibaba.csp.sentinel.slots.block.flow.FlowRule;


@ConfigurationProperties(ShiroSentinelProperties.PREFIX)
public class ShiroSentinelProperties{

	public static final String PREFIX = "shiro.sentinel";

	private boolean enabled = false;
	
	private List<AuthorityRule> authorityRules = new ArrayList<>();
	
	private List<FlowRule> flowRules = new ArrayList<>();
	
	private List<DegradeRule> degradeRules = new ArrayList<>();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public List<AuthorityRule> getAuthorityRules() {
		return authorityRules;
	}

	public void setAuthorityRules(List<AuthorityRule> authorityRules) {
		this.authorityRules = authorityRules;
	}

	public List<FlowRule> getFlowRules() {
		return flowRules;
	}

	public void setFlowRules(List<FlowRule> flowRules) {
		this.flowRules = flowRules;
	}

	public List<DegradeRule> getDegradeRules() {
		return degradeRules;
	}

	public void setDegradeRules(List<DegradeRule> degradeRules) {
		this.degradeRules = degradeRules;
	}
	
}
