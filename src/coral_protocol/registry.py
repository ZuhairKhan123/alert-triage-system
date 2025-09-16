"""
Coral Protocol registry for agent discovery and coordination
"""

import asyncio
import logging
import time
from typing import Dict, List, Set, Optional
from collections import defaultdict

from .message_types import CoralMessage, AgentCapability, AgentStatus, MessageType
from .exceptions import (
    AgentRegistrationError, 
    MessageRoutingError, 
    AgentNotFoundError,
    CapabilityNotFoundError
)


logger = logging.getLogger(__name__)


class CoralRegistry:
    """
    Coral Protocol registry for agent discovery and coordination
    
    This class manages agent registration, capability indexing, and message routing
    according to the Coral Protocol specification.
    """
    
    def __init__(self):
        # Agent management
        self.agents = {}  # agent_id -> CoralAgent
        self.agent_metadata = {}  # agent_id -> metadata dict
        
        # Capability indexing
        self.capabilities_index = defaultdict(list)  # capability_name -> [agent_ids]
        self.agent_capabilities = defaultdict(list)  # agent_id -> [capabilities]
        
        # Workflow tracking
        self.active_workflows = {}  # thread_id -> workflow_info
        self.message_history = {}   # thread_id -> [messages]
        
        # Performance metrics
        self.total_messages_routed = 0
        self.failed_message_count = 0
        self.registry_start_time = time.time()
        
        # Configuration
        self.max_message_history = 1000
        self.heartbeat_check_interval = 60
        
    async def register_agent(self, agent):
        """Register agent and index its capabilities"""
        try:
            if agent.agent_id in self.agents:
                raise AgentRegistrationError(
                    agent.agent_id,
                    "Agent already registered"
                )
            
            # Register the agent
            self.agents[agent.agent_id] = agent
            self.agent_metadata[agent.agent_id] = {
                'name': agent.name,
                'registration_time': time.time(),
                'capabilities': [cap.name for cap in agent.capabilities]
            }
            
            # Index capabilities
            for capability in agent.capabilities:
                self.capabilities_index[capability.name].append(agent.agent_id)
                self.agent_capabilities[agent.agent_id].append(capability)
                
            logger.info(f"Registered agent {agent.name} ({agent.agent_id}) with {len(agent.capabilities)} capabilities")
            
        except Exception as e:
            raise AgentRegistrationError(agent.agent_id, str(e))
            
    async def unregister_agent(self, agent_id: str):
        """Unregister an agent and clean up its capabilities"""
        if agent_id not in self.agents:
            raise AgentNotFoundError(agent_id)
            
        agent = self.agents[agent_id]
        
        # Remove from capability index
        for capability in self.agent_capabilities[agent_id]:
            if agent_id in self.capabilities_index[capability.name]:
                self.capabilities_index[capability.name].remove(agent_id)
                
        # Clean up
        del self.agents[agent_id]
        del self.agent_metadata[agent_id]
        del self.agent_capabilities[agent_id]
        
        logger.info(f"Unregistered agent {agent.name} ({agent_id})")
        
    async def discover_agents(self, required_capabilities: List[str], 
                            exclude_agents: Optional[List[str]] = None) -> List[str]:
        """
        Discover agents that have required capabilities
        
        Args:
            required_capabilities: List of capability names needed
            exclude_agents: Optional list of agent IDs to exclude
            
        Returns:
            List of agent IDs that have all required capabilities
        """
        if not required_capabilities:
            return list(self.agents.keys())
            
        exclude_agents = exclude_agents or []
        
        # Find agents with all required capabilities
        capable_agents = None
        
        for capability in required_capabilities:
            if capability not in self.capabilities_index:
                raise CapabilityNotFoundError(capability)
                
            agents_with_capability = set(self.capabilities_index[capability])
            
            if capable_agents is None:
                capable_agents = agents_with_capability
            else:
                capable_agents = capable_agents.intersection(agents_with_capability)
                
        # Filter out excluded agents and offline agents
        result = []
        for agent_id in capable_agents:
            if (agent_id not in exclude_agents and 
                agent_id in self.agents and 
                self.agents[agent_id].status == "online"):
                result.append(agent_id)
                
        logger.debug(f"Discovered {len(result)} agents with capabilities {required_capabilities}")
        return result
        
    async def route_message(self, message: CoralMessage):
        """Route message to target agent"""
        try:
            if message.receiver_id not in self.agents:
                raise MessageRoutingError(
                    message.id,
                    message.receiver_id,
                    "Target agent not found"
                )
                
            target_agent = self.agents[message.receiver_id]
            
            if target_agent.status != "online":
                raise MessageRoutingError(
                    message.id,
                    message.receiver_id,
                    f"Target agent is {target_agent.status}"
                )
                
            # Track message in workflow
            await self._track_message_in_workflow(message)
            
            # Route the message
            await target_agent.receive_message(message)
            
            self.total_messages_routed += 1
            logger.debug(f"Routed message {message.id} to agent {message.receiver_id}")
            
        except Exception as e:
            self.failed_message_count += 1
            logger.error(f"Failed to route message {message.id}: {e}")
            raise MessageRoutingError(message.id, message.receiver_id, str(e))
            
    async def _track_message_in_workflow(self, message: CoralMessage):
        """Track message as part of workflow execution"""
        thread_id = message.thread_id
        
        # Initialize workflow tracking if needed
        if thread_id not in self.active_workflows:
            self.active_workflows[thread_id] = {
                'start_time': time.time(),
                'message_count': 0,
                'agents_involved': set(),
                'last_activity': time.time()
            }
            self.message_history[thread_id] = []
            
        # Update workflow info
        workflow = self.active_workflows[thread_id]
        workflow['message_count'] += 1
        workflow['agents_involved'].add(message.sender_id)
        workflow['agents_involved'].add(message.receiver_id)
        workflow['last_activity'] = time.time()
        
        # Store message in history (with size limit)
        history = self.message_history[thread_id]
        history.append({
            'message_id': message.id,
            'sender_id': message.sender_id,
            'receiver_id': message.receiver_id,
            'message_type': message.message_type.value,
            'timestamp': message.timestamp.isoformat()
        })
        
        # Limit history size
        if len(history) > self.max_message_history:
            history.pop(0)
            
    async def get_workflow_status(self, thread_id: str) -> Optional[Dict]:
        """Get status of a specific workflow"""
        if thread_id not in self.active_workflows:
            return None
            
        workflow = self.active_workflows[thread_id]
        return {
            'thread_id': thread_id,
            'start_time': workflow['start_time'],
            'message_count': workflow['message_count'],
            'agents_involved': list(workflow['agents_involved']),
            'last_activity': workflow['last_activity'],
            'duration': time.time() - workflow['start_time'],
            'message_history': self.message_history.get(thread_id, [])
        }
        
    async def cleanup_completed_workflows(self):
        """Clean up workflows that have been inactive"""
        current_time = time.time()
        inactive_threshold = 300  # 5 minutes
        
        completed_workflows = []
        for thread_id, workflow in self.active_workflows.items():
            if current_time - workflow['last_activity'] > inactive_threshold:
                completed_workflows.append(thread_id)
                
        for thread_id in completed_workflows:
            del self.active_workflows[thread_id]
            if thread_id in self.message_history:
                del self.message_history[thread_id]
                
        if completed_workflows:
            logger.info(f"Cleaned up {len(completed_workflows)} inactive workflows")
            
    async def get_agent_status(self, agent_id: str) -> Optional[AgentStatus]:
        """Get status of a specific agent"""
        if agent_id in self.agents:
            return self.agents[agent_id].get_status()
        return None
        
    async def get_all_agent_statuses(self) -> List[AgentStatus]:
        """Get status of all registered agents"""
        statuses = []
        for agent in self.agents.values():
            statuses.append(agent.get_status())
        return statuses
        
    async def broadcast_message(self, message: CoralMessage, 
                              capability_filter: Optional[List[str]] = None):
        """
        Broadcast message to multiple agents
        
        Args:
            message: Message to broadcast (receiver_id will be ignored)
            capability_filter: Only send to agents with these capabilities
        """
        target_agents = []
        
        if capability_filter:
            target_agents = await self.discover_agents(capability_filter)
        else:
            target_agents = list(self.agents.keys())
            
        # Send to each target agent
        for agent_id in target_agents:
            broadcast_message = CoralMessage(
                id=message.id + f"_to_{agent_id}",
                sender_id=message.sender_id,
                receiver_id=agent_id,
                message_type=message.message_type,
                thread_id=message.thread_id,
                payload=message.payload,
                timestamp=message.timestamp,
                priority=message.priority
            )
            
            try:
                await self.route_message(broadcast_message)
            except Exception as e:
                logger.error(f"Failed to broadcast to agent {agent_id}: {e}")
                
    def get_registry_metrics(self) -> Dict:
        """Get registry performance metrics"""
        uptime = time.time() - self.registry_start_time
        
        return {
            'total_agents': len(self.agents),
            'total_capabilities': len(self.capabilities_index),
            'active_workflows': len(self.active_workflows),
            'total_messages_routed': self.total_messages_routed,
            'failed_message_count': self.failed_message_count,
            'success_rate': (
                (self.total_messages_routed / 
                 (self.total_messages_routed + self.failed_message_count))
                if (self.total_messages_routed + self.failed_message_count) > 0
                else 1.0
            ),
            'uptime_seconds': uptime,
            'messages_per_second': self.total_messages_routed / uptime if uptime > 0 else 0
        }
        
    async def health_check(self) -> Dict:
        """Perform registry health check"""
        online_agents = sum(1 for agent in self.agents.values() if agent.status == "online")
        
        return {
            'status': 'healthy' if online_agents > 0 else 'degraded',
            'total_agents': len(self.agents),
            'online_agents': online_agents,
            'active_workflows': len(self.active_workflows),
            'registry_uptime': time.time() - self.registry_start_time
        }
        
    def __repr__(self):
        return f"CoralRegistry(agents={len(self.agents)}, workflows={len(self.active_workflows)})"