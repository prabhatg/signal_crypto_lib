//! Scalable Deployment Configurations and Infrastructure Management
//! 
//! This module provides enterprise-grade deployment configurations including:
//! - Load balancing and clustering support
//! - Auto-scaling and resource management
//! - Health monitoring and service discovery
//! - Configuration management and deployment strategies
//! - Container orchestration and cloud integration

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::types::SignalError;

/// Deployment environment types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Environment {
    Development,
    Testing,
    Staging,
    Production,
    Custom(String),
}

/// Deployment strategy types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeploymentStrategy {
    BlueGreen,
    RollingUpdate,
    Canary,
    Recreate,
    Custom(String),
}

/// Load balancing algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
    LeastResponseTime,
    Random,
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Degraded,
    Unknown,
}

/// Deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub deployment_id: String,
    pub name: String,
    pub environment: Environment,
    pub strategy: DeploymentStrategy,
    pub replicas: u32,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub resource_limits: ResourceLimits,
    pub networking: NetworkConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub monitoring: MonitoringConfig,
    pub auto_scaling: AutoScalingConfig,
    pub load_balancer: LoadBalancerConfig,
}

/// Resource limits and requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    pub storage_request: String,
    pub storage_limit: String,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub service_port: u16,
    pub target_port: u16,
    pub protocol: String,
    pub ingress_enabled: bool,
    pub ingress_host: Option<String>,
    pub tls_enabled: bool,
    pub service_mesh_enabled: bool,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub persistent_volume_enabled: bool,
    pub storage_class: String,
    pub access_mode: String,
    pub size: String,
    pub backup_enabled: bool,
    pub backup_schedule: Option<String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub pod_security_context: PodSecurityContext,
    pub network_policies_enabled: bool,
    pub rbac_enabled: bool,
    pub service_account: String,
    pub secrets: Vec<String>,
    pub config_maps: Vec<String>,
}

/// Pod security context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSecurityContext {
    pub run_as_user: Option<u32>,
    pub run_as_group: Option<u32>,
    pub fs_group: Option<u32>,
    pub run_as_non_root: bool,
    pub read_only_root_filesystem: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub metrics_port: u16,
    pub metrics_path: String,
    pub health_check_enabled: bool,
    pub health_check_path: String,
    pub readiness_probe: ProbeConfig,
    pub liveness_probe: ProbeConfig,
}

/// Probe configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub initial_delay_seconds: u32,
    pub period_seconds: u32,
    pub timeout_seconds: u32,
    pub success_threshold: u32,
    pub failure_threshold: u32,
}

/// Auto-scaling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoScalingConfig {
    pub enabled: bool,
    pub target_cpu_utilization: u32,
    pub target_memory_utilization: u32,
    pub scale_up_stabilization: Duration,
    pub scale_down_stabilization: Duration,
    pub custom_metrics: Vec<CustomMetric>,
}

/// Custom scaling metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetric {
    pub name: String,
    pub target_value: f64,
    pub metric_type: MetricType,
}

/// Metric types for scaling
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MetricType {
    Resource,
    Pods,
    Object,
    External,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub algorithm: LoadBalancingAlgorithm,
    pub session_affinity: bool,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub max_connections_per_instance: u32,
    pub connection_timeout: Duration,
}

/// Service instance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub instance_id: String,
    pub host: String,
    pub port: u16,
    pub status: HealthStatus,
    pub last_health_check: SystemTime,
    pub metadata: HashMap<String, String>,
    pub load: f64,
    pub connections: u32,
}

/// Cluster manager for service orchestration
pub struct ClusterManager {
    instances: Arc<RwLock<HashMap<String, ServiceInstance>>>,
    load_balancer: LoadBalancer,
    health_monitor: HealthMonitor,
    auto_scaler: AutoScaler,
    config: DeploymentConfig,
}

/// Load balancer implementation
pub struct LoadBalancer {
    algorithm: LoadBalancingAlgorithm,
    instances: Arc<RwLock<HashMap<String, ServiceInstance>>>,
    current_index: Arc<RwLock<usize>>,
}

/// Health monitoring system
pub struct HealthMonitor {
    instances: Arc<RwLock<HashMap<String, ServiceInstance>>>,
    check_interval: Duration,
    timeout: Duration,
}

/// Auto-scaling system
pub struct AutoScaler {
    config: AutoScalingConfig,
    metrics_collector: MetricsCollector,
    scaling_decisions: Arc<RwLock<Vec<ScalingDecision>>>,
}

/// Metrics collection system
pub struct MetricsCollector {
    metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
}

/// Metric value with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub value: f64,
    pub timestamp: SystemTime,
    pub labels: HashMap<String, String>,
}

/// Scaling decision record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingDecision {
    pub decision_id: String,
    pub timestamp: SystemTime,
    pub action: ScalingAction,
    pub reason: String,
    pub current_replicas: u32,
    pub desired_replicas: u32,
    pub metrics: HashMap<String, f64>,
}

/// Scaling actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScalingAction {
    ScaleUp,
    ScaleDown,
    NoAction,
}

impl ClusterManager {
    /// Create new cluster manager
    pub fn new(config: DeploymentConfig) -> Self {
        let instances = Arc::new(RwLock::new(HashMap::new()));
        
        Self {
            load_balancer: LoadBalancer::new(
                config.load_balancer.algorithm.clone(),
                instances.clone(),
            ),
            health_monitor: HealthMonitor::new(
                instances.clone(),
                config.load_balancer.health_check_interval,
                config.load_balancer.health_check_timeout,
            ),
            auto_scaler: AutoScaler::new(config.auto_scaling.clone()),
            instances,
            config,
        }
    }

    /// Register service instance
    pub fn register_instance(&self, instance: ServiceInstance) -> Result<(), SignalError> {
        let mut instances = self.instances.write().unwrap();
        instances.insert(instance.instance_id.clone(), instance);
        Ok(())
    }

    /// Deregister service instance
    pub fn deregister_instance(&self, instance_id: &str) -> Result<(), SignalError> {
        let mut instances = self.instances.write().unwrap();
        instances.remove(instance_id);
        Ok(())
    }

    /// Get next available instance using load balancing
    pub fn get_next_instance(&self) -> Result<Option<ServiceInstance>, SignalError> {
        self.load_balancer.get_next_instance()
    }

    /// Update instance health status
    pub fn update_instance_health(
        &self,
        instance_id: &str,
        status: HealthStatus,
    ) -> Result<(), SignalError> {
        let mut instances = self.instances.write().unwrap();
        if let Some(instance) = instances.get_mut(instance_id) {
            instance.status = status;
            instance.last_health_check = SystemTime::now();
        }
        Ok(())
    }

    /// Perform health checks on all instances
    pub fn perform_health_checks(&self) -> Result<(), SignalError> {
        self.health_monitor.check_all_instances()
    }

    /// Evaluate auto-scaling decisions
    pub fn evaluate_scaling(&self) -> Result<Option<ScalingDecision>, SignalError> {
        self.auto_scaler.evaluate_scaling(&self.instances)
    }

    /// Get cluster statistics
    pub fn get_cluster_stats(&self) -> ClusterStats {
        let instances = self.instances.read().unwrap();
        let total_instances = instances.len();
        let healthy_instances = instances.values()
            .filter(|i| i.status == HealthStatus::Healthy)
            .count();
        let total_connections: u32 = instances.values()
            .map(|i| i.connections)
            .sum();
        let average_load = if total_instances > 0 {
            instances.values().map(|i| i.load).sum::<f64>() / total_instances as f64
        } else {
            0.0
        };

        ClusterStats {
            total_instances,
            healthy_instances,
            total_connections,
            average_load,
        }
    }
}

/// Cluster statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStats {
    pub total_instances: usize,
    pub healthy_instances: usize,
    pub total_connections: u32,
    pub average_load: f64,
}

impl LoadBalancer {
    pub fn new(
        algorithm: LoadBalancingAlgorithm,
        instances: Arc<RwLock<HashMap<String, ServiceInstance>>>,
    ) -> Self {
        Self {
            algorithm,
            instances,
            current_index: Arc::new(RwLock::new(0)),
        }
    }

    pub fn get_next_instance(&self) -> Result<Option<ServiceInstance>, SignalError> {
        let instances = self.instances.read().unwrap();
        let healthy_instances: Vec<&ServiceInstance> = instances.values()
            .filter(|i| i.status == HealthStatus::Healthy)
            .collect();

        if healthy_instances.is_empty() {
            return Ok(None);
        }

        let selected = match self.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                let mut index = self.current_index.write().unwrap();
                let selected = healthy_instances[*index % healthy_instances.len()];
                *index += 1;
                selected
            }
            LoadBalancingAlgorithm::LeastConnections => {
                healthy_instances.iter()
                    .min_by_key(|i| i.connections)
                    .unwrap()
            }
            LoadBalancingAlgorithm::LeastResponseTime => {
                healthy_instances.iter()
                    .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
                    .unwrap()
            }
            LoadBalancingAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let index = rng.gen_range(0..healthy_instances.len());
                healthy_instances[index]
            }
            _ => healthy_instances[0], // Default to first instance
        };

        Ok(Some(selected.clone()))
    }
}

impl HealthMonitor {
    pub fn new(
        instances: Arc<RwLock<HashMap<String, ServiceInstance>>>,
        check_interval: Duration,
        timeout: Duration,
    ) -> Self {
        Self {
            instances,
            check_interval,
            timeout,
        }
    }

    pub fn check_all_instances(&self) -> Result<(), SignalError> {
        let instances = self.instances.read().unwrap();
        for instance in instances.values() {
            // In a real implementation, this would perform actual health checks
            // For now, we'll simulate health check logic
            self.check_instance_health(instance)?;
        }
        Ok(())
    }

    fn check_instance_health(&self, instance: &ServiceInstance) -> Result<(), SignalError> {
        // Simulate health check - in reality this would make HTTP requests
        // or check service endpoints
        println!("Checking health of instance: {}", instance.instance_id);
        Ok(())
    }
}

impl AutoScaler {
    pub fn new(config: AutoScalingConfig) -> Self {
        Self {
            config,
            metrics_collector: MetricsCollector::new(),
            scaling_decisions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn evaluate_scaling(
        &self,
        instances: &Arc<RwLock<HashMap<String, ServiceInstance>>>,
    ) -> Result<Option<ScalingDecision>, SignalError> {
        if !self.config.enabled {
            return Ok(None);
        }

        let current_metrics = self.metrics_collector.collect_metrics(instances)?;
        let current_replicas = {
            let instances = instances.read().unwrap();
            instances.len() as u32
        };

        // Evaluate CPU utilization
        let cpu_utilization = current_metrics.get("cpu_utilization").unwrap_or(&0.0);
        let memory_utilization = current_metrics.get("memory_utilization").unwrap_or(&0.0);

        let desired_replicas = if *cpu_utilization > self.config.target_cpu_utilization as f64 ||
                                  *memory_utilization > self.config.target_memory_utilization as f64 {
            // Scale up
            (current_replicas + 1).min(10) // Max 10 replicas for safety
        } else if *cpu_utilization < (self.config.target_cpu_utilization as f64 * 0.5) &&
                  *memory_utilization < (self.config.target_memory_utilization as f64 * 0.5) {
            // Scale down
            (current_replicas.saturating_sub(1)).max(1) // Min 1 replica
        } else {
            current_replicas
        };

        if desired_replicas != current_replicas {
            let action = if desired_replicas > current_replicas {
                ScalingAction::ScaleUp
            } else {
                ScalingAction::ScaleDown
            };

            let decision = ScalingDecision {
                decision_id: Uuid::new_v4().to_string(),
                timestamp: SystemTime::now(),
                action,
                reason: format!(
                    "CPU: {:.1}%, Memory: {:.1}%",
                    cpu_utilization, memory_utilization
                ),
                current_replicas,
                desired_replicas,
                metrics: current_metrics,
            };

            // Store decision
            {
                let mut decisions = self.scaling_decisions.write().unwrap();
                decisions.push(decision.clone());
            }

            Ok(Some(decision))
        } else {
            Ok(None)
        }
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn collect_metrics(
        &self,
        instances: &Arc<RwLock<HashMap<String, ServiceInstance>>>,
    ) -> Result<HashMap<String, f64>, SignalError> {
        let instances = instances.read().unwrap();
        let mut metrics = HashMap::new();

        if !instances.is_empty() {
            // Calculate average CPU utilization (simulated)
            let avg_cpu = instances.values()
                .map(|i| i.load * 100.0) // Convert load to percentage
                .sum::<f64>() / instances.len() as f64;

            // Calculate average memory utilization (simulated)
            let avg_memory = instances.values()
                .map(|i| (i.connections as f64 / 100.0) * 100.0) // Simulate memory based on connections
                .sum::<f64>() / instances.len() as f64;

            metrics.insert("cpu_utilization".to_string(), avg_cpu);
            metrics.insert("memory_utilization".to_string(), avg_memory);
            metrics.insert("total_connections".to_string(), 
                instances.values().map(|i| i.connections as f64).sum());
        }

        Ok(metrics)
    }
}

/// Generate Kubernetes deployment YAML
pub fn generate_kubernetes_deployment(config: &DeploymentConfig) -> String {
    format!(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  labels:
    app: {name}
    environment: {environment:?}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: {name}
        image: signal-crypto-lib:latest
        ports:
        - containerPort: {port}
        resources:
          requests:
            cpu: {cpu_request}
            memory: {memory_request}
          limits:
            cpu: {cpu_limit}
            memory: {memory_limit}
        livenessProbe:
          httpGet:
            path: {health_path}
            port: {port}
          initialDelaySeconds: {liveness_delay}
          periodSeconds: {liveness_period}
        readinessProbe:
          httpGet:
            path: {health_path}
            port: {port}
          initialDelaySeconds: {readiness_delay}
          periodSeconds: {readiness_period}
---
apiVersion: v1
kind: Service
metadata:
  name: {name}-service
spec:
  selector:
    app: {name}
  ports:
  - port: {service_port}
    targetPort: {target_port}
  type: LoadBalancer
"#,
        name = config.name,
        environment = config.environment,
        replicas = config.replicas,
        port = config.networking.target_port,
        service_port = config.networking.service_port,
        target_port = config.networking.target_port,
        cpu_request = config.resource_limits.cpu_request,
        memory_request = config.resource_limits.memory_request,
        cpu_limit = config.resource_limits.cpu_limit,
        memory_limit = config.resource_limits.memory_limit,
        health_path = config.monitoring.health_check_path,
        liveness_delay = config.monitoring.liveness_probe.initial_delay_seconds,
        liveness_period = config.monitoring.liveness_probe.period_seconds,
        readiness_delay = config.monitoring.readiness_probe.initial_delay_seconds,
        readiness_period = config.monitoring.readiness_probe.period_seconds,
    )
}

/// Generate Docker Compose configuration
pub fn generate_docker_compose(config: &DeploymentConfig) -> String {
    format!(r#"
version: '3.8'
services:
  {name}:
    image: signal-crypto-lib:latest
    ports:
      - "{service_port}:{target_port}"
    environment:
      - ENVIRONMENT={environment:?}
    deploy:
      replicas: {replicas}
      resources:
        limits:
          cpus: '{cpu_limit}'
          memory: {memory_limit}
        reservations:
          cpus: '{cpu_request}'
          memory: {memory_request}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{target_port}{health_path}"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
"#,
        name = config.name,
        environment = config.environment,
        replicas = config.replicas,
        service_port = config.networking.service_port,
        target_port = config.networking.target_port,
        cpu_limit = config.resource_limits.cpu_limit,
        memory_limit = config.resource_limits.memory_limit,
        cpu_request = config.resource_limits.cpu_request,
        memory_request = config.resource_limits.memory_request,
        health_path = config.monitoring.health_check_path,
    )
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            deployment_id: Uuid::new_v4().to_string(),
            name: "signal-crypto-service".to_string(),
            environment: Environment::Production,
            strategy: DeploymentStrategy::RollingUpdate,
            replicas: 3,
            min_replicas: 1,
            max_replicas: 10,
            resource_limits: ResourceLimits::default(),
            networking: NetworkConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            monitoring: MonitoringConfig::default(),
            auto_scaling: AutoScalingConfig::default(),
            load_balancer: LoadBalancerConfig::default(),
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_request: "100m".to_string(),
            cpu_limit: "500m".to_string(),
            memory_request: "128Mi".to_string(),
            memory_limit: "512Mi".to_string(),
            storage_request: "1Gi".to_string(),
            storage_limit: "10Gi".to_string(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            service_port: 8080,
            target_port: 8080,
            protocol: "TCP".to_string(),
            ingress_enabled: true,
            ingress_host: Some("signal-crypto.example.com".to_string()),
            tls_enabled: true,
            service_mesh_enabled: false,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            persistent_volume_enabled: true,
            storage_class: "fast-ssd".to_string(),
            access_mode: "ReadWriteOnce".to_string(),
            size: "10Gi".to_string(),
            backup_enabled: true,
            backup_schedule: Some("0 2 * * *".to_string()), // Daily at 2 AM
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pod_security_context: PodSecurityContext::default(),
            network_policies_enabled: true,
            rbac_enabled: true,
            service_account: "signal-crypto-service".to_string(),
            secrets: vec!["signal-crypto-secrets".to_string()],
            config_maps: vec!["signal-crypto-config".to_string()],
        }
    }
}

impl Default for PodSecurityContext {
    fn default() -> Self {
        Self {
            run_as_user: Some(1000),
            run_as_group: Some(1000),
            fs_group: Some(1000),
            run_as_non_root: true,
            read_only_root_filesystem: true,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            metrics_port: 9090,
            metrics_path: "/metrics".to_string(),
            health_check_enabled: true,
            health_check_path: "/health".to_string(),
            readiness_probe: ProbeConfig::default(),
            liveness_probe: ProbeConfig::default(),
        }
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            initial_delay_seconds: 30,
            period_seconds: 10,
            timeout_seconds: 5,
            success_threshold: 1,
            failure_threshold: 3,
        }
    }
}

impl Default for AutoScalingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_cpu_utilization: 70,
            target_memory_utilization: 80,
            scale_up_stabilization: Duration::from_secs(300),   // 5 minutes
            scale_down_stabilization: Duration::from_secs(600), // 10 minutes
            custom_metrics: Vec::new(),
        }
    }
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            session_affinity: false,
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            max_connections_per_instance: 1000,
            connection_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_config_creation() {
        let config = DeploymentConfig::default();
        assert_eq!(config.name, "signal-crypto-service");
        assert_eq!(config.replicas, 3);
        assert_eq!(config.environment, Environment::Production);
    }

    #[test]
    fn test_cluster_manager() {
        let config = DeploymentConfig::default();
        let cluster = ClusterManager::new(config);

        let instance = ServiceInstance {
            instance_id: "instance-1".to_string(),
            host: "192.168.1.100".to_string(),
            port: 8080,
            status: HealthStatus::Healthy,
            last_health_check: SystemTime::now(),
            metadata: HashMap::new(),
            load: 0.5,
            connections: 10,
        };

        let result = cluster.register_instance(instance);
        assert!(result.is_ok());

        let stats = cluster.get_cluster_stats();
        assert_eq!(stats.total_instances, 1);
        assert_eq!(stats.healthy_instances, 1);
    }

    #[test]
    fn test_load_balancer() {
        let instances = Arc::new(RwLock::new(HashMap::new()));
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin, instances.clone());

        // Add test instances
        {
            let mut instances_map = instances.write().unwrap();
            for i in 0..3 {
                let instance = ServiceInstance {
                    instance_id: format!("instance-{}", i),
                    host: format!("192.168.1.{}", 100 + i),
                    port: 8080,
                    status: HealthStatus::Healthy,
                    last_health_check: SystemTime::now(),
                    metadata: HashMap::new(),
                    load: 0.3,
                    connections: 5,
                };
                instances_map.insert(instance.instance_id.clone(), instance);
            }
        }

        // Test round-robin selection
        for _ in 0..6 {
            let result = lb.get_next_instance();
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }
    }

    #[test]
    fn test_kubernetes_yaml_generation() {
        let config = DeploymentConfig::default();
        let yaml = generate_kubernetes_deployment(&config);
        
        assert!(yaml.contains("apiVersion: apps/v1"));
        assert!(yaml.contains("kind: Deployment"));
        assert!(yaml.contains("signal-crypto-service"));
    }

    #[test]
    fn test_docker_compose_generation() {
        let config = DeploymentConfig::default();
        let compose = generate_docker_compose(&config);
        
        assert!(compose.contains("version: '3.8'"));
        assert!(compose.contains("signal-crypto-service"));
        assert!(compose.contains("replicas: 3"));
    }
}