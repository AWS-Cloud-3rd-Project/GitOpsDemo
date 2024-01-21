- Chart.yaml: 차트에 대한 정보를 담고 있는 파일.

- values.yaml: 파라미터 값을 정의하는 파일.

- templates/: Kubernetes 매니페스트 템플릿들을 포함하는 디렉토리.

- charts/: 종속 차트들을 포함하는 디렉토리 (선택적)

## 이미지 설정

- Deployment 매니페스트

values.yaml에서 정의된 imagePullSecrets, replicaCount, 그리고 image 설정을 참조

- Ingress 매니페스트

AWS의 ALB를 사용하기 위한 필요한 주석들이 설정되어 있고, 차트에 의해 생성된 서비스를 가리키고 있습니다.

경로는 모든 트래픽을 서비스로 라우팅하기 위한 /* 패턴으로 설정

- Service 매니페스트

NodePort 서비스 타입과 포트 번호가 values.yaml에 정의된 대로 설정되어 있으며, 이는 EKS 클러스터 외부로 서비스를 노출하기 위한 설정

- Chart.yaml

차트에 대한 기본 정보

- values.yaml

사용할 이미지, 서비스 타입 및 포트, 이미지 풀 시크릿
