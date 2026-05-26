# Threat Intel Board — Mock Frontend

Jira-like ticket board for the Threat Intelligence Classification & Routing pipeline.
Receives threat digests from the AWS pipeline, displays them by team, and lets analysts review/update tickets.

## Run locally

```bash
npm install
node server.js
# open http://localhost:3000
```

## Deploy to AWS ECS (Fargate)

### Prerequisites

- AWS CLI v2 configured (`aws configure`)
- Docker running
- Set `REGION` and `ACCOUNT` below to match your AWS environment

```bash
REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=threat-intel-board
```

### 1. Create ECR repository (once)

```bash
aws ecr create-repository --repository-name $REPO --region $REGION
```

### 2. Build and push image

> **Important:** The Dockerfile pins `--platform=linux/amd64`. If you remove that
> flag from the Dockerfile, pass `--platform linux/amd64` to `docker build`
> explicitly — Fargate runs x86_64 by default.

```bash
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$REGION.amazonaws.com

docker build -t $REPO .
docker tag $REPO:latest $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
docker push $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
```

### 3. Create ECS cluster (once)

```bash
aws ecs create-cluster --cluster-name threat-intel --region $REGION
```

### 4. Register task definition

Create a file `task-def.json`:

```json
{
  "family": "threat-intel-board",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::<ACCOUNT>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "threat-intel-board",
      "image": "<ACCOUNT>.dkr.ecr.ap-southeast-2.amazonaws.com/threat-intel-board:latest",
      "portMappings": [{ "containerPort": 3000, "protocol": "tcp" }],
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "wget -qO- http://localhost:3000/api/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/threat-intel-board",
          "awslogs-region": "ap-southeast-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://task-def.json --region $REGION
```

> **IAM note:** The `ecsTaskExecutionRole` needs the managed policy
> `AmazonECSTaskExecutionRolePolicy` (allows pulling from ECR and writing to
> CloudWatch Logs). Create it once if it doesn't exist:
>
> ```bash
> aws iam create-role --role-name ecsTaskExecutionRole \
>   --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
> aws iam attach-role-policy --role-name ecsTaskExecutionRole \
>   --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
> ```

### 5. Create the service

```bash
aws ecs create-service \
  --cluster threat-intel \
  --service-name threat-intel-board \
  --task-definition threat-intel-board \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_ID>],securityGroups=[<SG_ID>],assignPublicIp=ENABLED}" \
  --region $REGION
```

Replace `<SUBNET_ID>` and `<SG_ID>` with your VPC's public subnet and a security
group that allows inbound TCP 3000 (or 80/443 if behind an ALB).

### 6. Redeploy after changes

```bash
# rebuild and push (step 2 above), then force a new deployment:
aws ecs update-service \
  --cluster threat-intel \
  --service threat-intel-board \
  --force-new-deployment \
  --region $REGION
```

### 7. Point your AWS pipeline at the board

Get the public IP from the running task:

```bash
TASK_ARN=$(aws ecs list-tasks --cluster threat-intel --service-name threat-intel-board \
  --query "taskArns[0]" --output text --region $REGION)

aws ecs describe-tasks --cluster threat-intel --tasks $TASK_ARN \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" \
  --output text --region $REGION
```

Or if you have an ALB in front of the service, use the ALB DNS name. Then
redeploy your CDK stack with:

```bash
WEBHOOK_URL=https://<ecs-url>/api/tickets npx cdk deploy
```

## API

| Method | Path                     | Description                                |
| ------ | ------------------------ | ------------------------------------------ |
| GET    | `/api/health`            | Health check                               |
| GET    | `/api/teams`             | List all teams with ticket counts          |
| GET    | `/api/tickets?team=<id>` | List tickets (optionally filtered by team) |
| GET    | `/api/ticket/:id`        | Get single ticket                          |
| POST   | `/api/tickets`           | Ingest new ticket from pipeline            |
| POST   | `/api/update-ticket/:id` | Update status/severity/add comment         |

### POST `/api/tickets` payload

```json
{
  "threat_id": "...",
  "stix_id": "...",
  "title": "...",
  "asset_category": "scada",
  "asset_category_display": "SCADA",
  "severity": "high",
  "confidence": 0.92,
  "summary": "...",
  "affected_assets": ["Device A"],
  "cve_ids": ["CVE-2024-XXXXX"],
  "assessed_at": "2026-05-25T00:00:00Z",
  "mark_processed_url_hint": "POST /threats/{id}/processed"
}
```

Unknown `asset_category` values are routed to the **Service Desk** team.

### POST `/api/update-ticket/:id` payload

```json
{
  "status": "in_progress",
  "severity": "medium",
  "comment": "De-escalated after review."
}
```

All fields optional.

## Tear down

```bash
aws ecs update-service --cluster threat-intel --service threat-intel-board --desired-count 0 --region $REGION
aws ecs delete-service --cluster threat-intel --service threat-intel-board --region $REGION
aws ecs delete-cluster --cluster threat-intel --region $REGION
aws ecr delete-repository --repository-name $REPO --region $REGION --force
```
