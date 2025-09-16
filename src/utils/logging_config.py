"""
Logging configuration utility
"""

import logging
import logging.handlers
import os
import sys
from typing import Dict, Any
import structlog


def setup_logging(config: Dict[str, Any]):
    """
    Setup structured logging for the application
    
    Args:
        config: Logging configuration dictionary
    """
    
    # Get configuration values
    log_level = config.get("level", "INFO")
    log_format = config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    log_file = config.get("file")
    
    # Configure standard logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=_create_handlers(log_file, config)
    )
    
    # Configure structlog for structured logging
    _configure_structlog(config)
    
    # Set log levels for specific modules
    _set_module_log_levels(config)
    
    logging.info("Logging configuration complete")


def _create_handlers(log_file: str, config: Dict[str, Any]) -> list:
    """Create logging handlers"""
    
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter(config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    )
    handlers.append(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=config.get("max_file_size", 10 * 1024 * 1024),  # 10MB default
            backupCount=config.get("backup_count", 5)
        )
        
        file_handler.setFormatter(
            logging.Formatter(config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        )
        handlers.append(file_handler)
    
    return handlers


def _configure_structlog(config: Dict[str, Any]):
    """Configure structlog for structured logging"""
    
    # Determine output format
    if config.get("structured", False):
        # JSON output for production
        renderer = structlog.processors.JSONRenderer()
    else:
        # Human-readable output for development
        renderer = structlog.dev.ConsoleRenderer(colors=True)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            renderer
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def _set_module_log_levels(config: Dict[str, Any]):
    """Set log levels for specific modules"""
    
    module_levels = config.get("module_levels", {})
    
    # Default module levels to reduce noise
    default_levels = {
        "asyncio": "WARNING",
        "aiohttp": "WARNING",
        "urllib3": "WARNING",
        "requests": "WARNING"
    }
    
    # Merge with user configuration
    all_levels = {**default_levels, **module_levels}
    
    for module_name, level in all_levels.items():
        logging.getLogger(module_name).setLevel(getattr(logging, level.upper()))


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a structured logger instance
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


class SecurityAuditLogger:
    """
    Specialized logger for security events
    
    This logger ensures all security-related events are properly logged
    with appropriate metadata for compliance and investigation purposes.
    """
    
    def __init__(self):
        self.logger = get_logger("security_audit")
        
    def log_alert_processed(self, alert_id: str, workflow_id: str, 
                          decision: str, confidence: float, 
                          metadata: Dict[str, Any] = None):
        """Log alert processing completion"""
        
        self.logger.info(
            "alert_processed",
            alert_id=alert_id,
            workflow_id=workflow_id,
            decision=decision,
            confidence=confidence,
            metadata=metadata or {}
        )
        
    def log_false_positive_detected(self, alert_id: str, reasoning: list,
                                  confidence: float):
        """Log false positive detection"""
        
        self.logger.info(
            "false_positive_detected",
            alert_id=alert_id,
            reasoning=reasoning,
            confidence=confidence
        )
        
    def log_escalation(self, alert_id: str, from_severity: str, 
                      to_severity: str, reason: str):
        """Log alert escalation"""
        
        self.logger.warning(
            "alert_escalated",
            alert_id=alert_id,
            from_severity=from_severity,
            to_severity=to_severity,
            reason=reason
        )
        
    def log_agent_communication(self, sender_id: str, receiver_id: str,
                              message_type: str, thread_id: str):
        """Log agent communication for audit trail"""
        
        self.logger.debug(
            "agent_communication",
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_type=message_type,
            thread_id=thread_id
        )
        
    def log_security_violation(self, violation_type: str, agent_id: str,
                             details: Dict[str, Any]):
        """Log security violations"""
        
        self.logger.error(
            "security_violation",
            violation_type=violation_type,
            agent_id=agent_id,
            details=details
        )
        
    def log_system_event(self, event_type: str, details: Dict[str, Any]):
        """Log system-level security events"""
        
        self.logger.info(
            "system_event",
            event_type=event_type,
            details=details
        )


class PerformanceLogger:
    """Logger for performance metrics and timing"""
    
    def __init__(self):
        self.logger = get_logger("performance")
        
    def log_workflow_timing(self, workflow_id: str, agent_id: str,
                          operation: str, duration_ms: float):
        """Log operation timing"""
        
        self.logger.info(
            "operation_timing",
            workflow_id=workflow_id,
            agent_id=agent_id,
            operation=operation,
            duration_ms=duration_ms
        )
        
    def log_queue_metrics(self, agent_id: str, queue_size: int,
                         max_queue_size: int):
        """Log queue metrics"""
        
        self.logger.debug(
            "queue_metrics",
            agent_id=agent_id,
            queue_size=queue_size,
            max_queue_size=max_queue_size,
            utilization_percent=(queue_size / max_queue_size) * 100
        )
        
    def log_throughput_metrics(self, agent_id: str, messages_per_second: float,
                             average_processing_time: float):
        """Log throughput metrics"""
        
        self.logger.info(
            "throughput_metrics",
            agent_id=agent_id,
            messages_per_second=messages_per_second,
            average_processing_time=average_processing_time
        )


def timing_decorator(logger_name: str = None):
    """
    Decorator to log function execution time
    
    Args:
        logger_name: Name of logger to use (defaults to function's module)
        
    Returns:
        Decorated function
    """
    
    def decorator(func):
        import time
        import functools
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            logger = get_logger(logger_name or func.__module__)
            
            try:
                result = await func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                logger.debug(
                    "function_timing",
                    function=func.__name__,
                    duration_ms=duration,
                    success=True
                )
                
                return result
                
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                
                logger.error(
                    "function_timing",
                    function=func.__name__,
                    duration_ms=duration,
                    success=False,
                    error=str(e)
                )
                
                raise
                
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            logger = get_logger(logger_name or func.__module__)
            
            try:
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                logger.debug(
                    "function_timing",
                    function=func.__name__,
                    duration_ms=duration,
                    success=True
                )
                
                return result
                
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                
                logger.error(
                    "function_timing",
                    function=func.__name__,
                    duration_ms=duration,
                    success=False,
                    error=str(e)
                )
                
                raise
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
            
    return decorator