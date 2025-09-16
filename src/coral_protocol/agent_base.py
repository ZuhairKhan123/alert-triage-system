"""
Base agent class for Coral Protocol
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

from .message_types import CoralMessage, AgentCapability, AgentStatus, MessageType
from .exceptions import CoralException, AgentBusyError


logger = logging.getLogger(__name__)


class CoralAgent(ABC):
    """
    Base class for all Coral Protocol agents
    
    This class provides the foundational functionality for agents in the Coral
    ecosystem, including message handling, capability registration, and lifecycle management.
    """
    
    def __init__(self, agent_id: str, name: str, capabilities: List[AgentCapability], 
                 max_queue_size: int = 1000):
        self.agent_id = agent_id
        self.name = name
        self.capabilities = capabilities
        self.max_queue_size = max_queue_size
        
        # Communication infrastructure
        self.message_queue = asyncio.Queue(maxsize=max_queue_size)
        self.active_threads = {}
        self.coral_registry = None
        
        # Status tracking
        self.status = "offline"
        self.last_heartbeat = time.time()
        self.processed_messages = 0
        self.error_count = 0
        
        # Event handlers
        self._message_handlers = {}
        self._setup_default_handlers()
        
        # Configuration
        self.heartbeat_interval = 30  # seconds
        self.message_timeout = 60     # seconds
        
    def _setup_default_handlers(self):
        """Setup default message handlers"""
        self._message_handlers[MessageType.HEARTBEAT] = self._handle_heartbeat
        self._message_handlers[MessageType.ERROR] = self._handle_error
        
    async def register_with_coral(self, coral_registry):
        """Register agent and capabilities with Coral Protocol"""
        self.coral_registry = coral_registry
        await coral_registry.register_agent(self)
        self.status = "online"
        logger.info(f"Agent {self.name} ({self.agent_id}) registered with Coral Protocol")
        
    async def send_message(self, message: CoralMessage):
        """Send message through Coral Protocol"""
        if not self.coral_registry:
            raise CoralException("Agent not registered with Coral Protocol")
            
        try:
            await self.coral_registry.route_message(message)
            logger.debug(f"Agent {self.agent_id} sent message {message.id} to {message.receiver_id}")
        except Exception as e:
            logger.error(f"Failed to send message {message.id}: {e}")
            self.error_count += 1
            raise
            
    async def receive_message(self, message: CoralMessage):
        """Receive message from Coral Protocol"""
        try:
            if self.message_queue.full():
                raise AgentBusyError(
                    self.agent_id,
                    self.message_queue.qsize(),
                    self.max_queue_size
                )
                
            await self.message_queue.put(message)
            logger.debug(f"Agent {self.agent_id} received message {message.id}")
            
        except Exception as e:
            logger.error(f"Failed to receive message {message.id}: {e}")
            self.error_count += 1
            raise
            
    async def process_messages(self):
        """Main message processing loop"""
        logger.info(f"Starting message processing for agent {self.name}")
        
        while self.status in ["online", "busy"]:
            try:
                # Process messages with timeout
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=1.0
                )
                
                await self._process_single_message(message)
                self.processed_messages += 1
                
            except asyncio.TimeoutError:
                # No message received, continue loop
                continue
            except Exception as e:
                logger.error(f"Error processing message in {self.name}: {e}")
                self.error_count += 1
                
        logger.info(f"Message processing stopped for agent {self.name}")
        
    async def _process_single_message(self, message: CoralMessage):
        """Process a single message"""
        try:
            # Update thread tracking
            if message.thread_id not in self.active_threads:
                self.active_threads[message.thread_id] = {
                    'start_time': time.time(),
                    'message_count': 0
                }
            
            self.active_threads[message.thread_id]['message_count'] += 1
            
            # Route to appropriate handler
            if message.message_type in self._message_handlers:
                await self._message_handlers[message.message_type](message)
            else:
                await self.handle_message(message)
                
            # Clean up completed threads
            self._cleanup_threads()
            
        except Exception as e:
            logger.error(f"Error processing message {message.id}: {e}")
            await self._send_error_response(message, str(e))
            
    async def _send_error_response(self, original_message: CoralMessage, error: str):
        """Send error response for failed message processing"""
        if self.coral_registry:
            error_message = original_message.create_reply(
                sender_id=self.agent_id,
                payload={
                    "error": error,
                    "original_message_id": original_message.id
                },
                message_type=MessageType.ERROR
            )
            await self.send_message(error_message)
            
    def _cleanup_threads(self):
        """Clean up old thread tracking data"""
        current_time = time.time()
        expired_threads = []
        
        for thread_id, thread_info in self.active_threads.items():
            if current_time - thread_info['start_time'] > 300:  # 5 minutes
                expired_threads.append(thread_id)
                
        for thread_id in expired_threads:
            del self.active_threads[thread_id]
            
    async def _handle_heartbeat(self, message: CoralMessage):
        """Handle heartbeat messages"""
        self.last_heartbeat = time.time()
        
        # Send heartbeat response
        response = message.create_reply(
            sender_id=self.agent_id,
            payload={
                "status": self.status,
                "queue_size": self.message_queue.qsize(),
                "active_threads": len(self.active_threads),
                "processed_messages": self.processed_messages,
                "error_count": self.error_count
            }
        )
        await self.send_message(response)
        
    async def _handle_error(self, message: CoralMessage):
        """Handle error messages"""
        logger.error(f"Received error message: {message.payload}")
        
    @abstractmethod
    async def handle_message(self, message: CoralMessage):
        """
        Handle messages specific to this agent type
        
        Override in subclasses to implement agent-specific message processing
        """
        raise NotImplementedError("Subclasses must implement handle_message")
        
    def register_message_handler(self, message_type: MessageType, handler):
        """Register a custom message handler"""
        self._message_handlers[message_type] = handler
        
    def get_status(self) -> AgentStatus:
        """Get current agent status"""
        return AgentStatus(
            agent_id=self.agent_id,
            name=self.name,
            status=self.status,
            last_heartbeat=self.last_heartbeat,
            message_queue_size=self.message_queue.qsize(),
            active_threads=len(self.active_threads),
            processed_messages=self.processed_messages,
            error_count=self.error_count
        )
        
    async def shutdown(self):
        """Gracefully shutdown the agent"""
        logger.info(f"Shutting down agent {self.name}")
        self.status = "offline"
        
        # Process remaining messages (with timeout)
        try:
            while not self.message_queue.empty():
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=1.0
                )
                await self._process_single_message(message)
        except asyncio.TimeoutError:
            pass
            
        logger.info(f"Agent {self.name} shutdown complete")
        
    def __repr__(self):
        return f"CoralAgent(id={self.agent_id}, name={self.name}, status={self.status})"