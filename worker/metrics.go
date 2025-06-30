package worker

import (
	"context"
	"sync"
	"time"

	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	taskDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rofl_app_backend_worker_task_duration_seconds",
		Help: "Duration of tasks",
		Buckets: []float64{
			1, 5, 10, 20,
			30, 40, 50, 60, 70, 80, 90, 100, 110, 120,
			140, 160, 180, 240, 300,
		},
	}, []string{"task_name"})

	taskCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rofl_app_backend_worker_task_total",
		Help: "Total count of tasks",
	}, []string{"task_name", "status"})

	tasksCollectors = []prometheus.Collector{
		taskDuration,
		taskCount,
	}
	metricsOnce sync.Once
)

var _ asynq.Handler = (*metricsProcessor)(nil)

type metricsProcessor struct {
	taskName     string
	innerHandler asynq.Handler
}

func (p *metricsProcessor) ProcessTask(ctx context.Context, t *asynq.Task) error {
	startTime := time.Now()
	err := p.innerHandler.ProcessTask(ctx, t)
	if err != nil {
		// Only observe the duration if the task was successful.
		taskDuration.WithLabelValues(p.taskName).Observe(time.Since(startTime).Seconds())
	}
	taskCount.WithLabelValues(p.taskName, taskStatus(err)).Inc()
	return err
}

func taskStatus(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}

func newMetricsWrapper(taskName string, innerHandler asynq.Handler) *metricsProcessor {
	metricsOnce.Do(func() {
		prometheus.MustRegister(tasksCollectors...)
	})

	return &metricsProcessor{
		taskName:     taskName,
		innerHandler: innerHandler,
	}
}
