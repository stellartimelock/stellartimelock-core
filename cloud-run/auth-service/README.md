# Stellar TimeLock — Cloud Run Auth Service

Thin FastAPI proxy that exchanges Google OAuth authorization codes for
access/refresh tokens **server-side**, keeping `client_secret` off the
Expo mobile client.

---

## Endpoints

| Method | Path              | Purpose                                                                 |
|--------|-------------------|-------------------------------------------------------------------------|
| POST   | `/oauth/exchange` | Authorization code → `{access_token, refresh_token, email, ...}`        |
| POST   | `/oauth/refresh`  | `refresh_token` → fresh `access_token`                                  |
| POST   | `/oauth/revoke`   | Best-effort token revocation (sign-out)                                 |
| GET    | `/healthz`        | Cloud Run health probe                                                  |

---

## One-time setup — Artifact Registry & IAM

You already created the `auth-repo` Docker Artifact Registry in `us-east5`.
If you haven't, run:

```bash
gcloud artifacts repositories create auth-repo \
  --repository-format=docker \
  --location=us-east5 \
  --description="Stellar TimeLock backend images"
```

Authenticate Docker to Artifact Registry once:

```bash
gcloud auth configure-docker us-east5-docker.pkg.dev
```

Enable required APIs (safe to re-run):

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iamcredentials.googleapis.com
```

---

## Environment variables the service needs

Set these on the Cloud Run service (NOT baked into the image):

| Var                          | Example                                                              | Where to get it                                         |
|------------------------------|----------------------------------------------------------------------|---------------------------------------------------------|
| `GOOGLE_CLIENT_ID_WEB`       | `699926185020-xxxx.apps.googleusercontent.com`                       | Google Cloud Console → Credentials → Web OAuth client   |
| `GOOGLE_CLIENT_SECRET_WEB`   | `GOCSPX-xxxxxxxxxxxxxxxxxxxxxx`                                      | Same OAuth client — click **Add Secret**                |
| `GOOGLE_CLIENT_ID_ANDROID`   | `699926185020-jnuqd4qq8mmpf01plv8d78ceg7nq1lh5.apps.googleusercontent.com` | Google Cloud Console → Credentials → Android OAuth client |
| `ALLOWED_ORIGINS` (optional) | `https://stellartimelock.com,https://<your-expo-preview>.emergentagent.com` | Comma-separated CORS allow-list; leave blank for `*`    |

> **Recommended:** store `GOOGLE_CLIENT_SECRET_WEB` in **Secret Manager**
> instead of a plaintext env var (commands below).

---

## Build & deploy — option A (Cloud Build, easiest)

One command builds the image from source, pushes it to `auth-repo`, and
deploys it to Cloud Run:

```bash
cd /app/cloud-run/auth-service

PROJECT_ID=$(gcloud config get-value project)
SERVICE=stellartimelock-auth
REGION=us-east5
IMAGE=us-east5-docker.pkg.dev/${PROJECT_ID}/auth-repo/${SERVICE}:latest

# 1. Build & push via Cloud Build
gcloud builds submit --tag ${IMAGE}

# 2. Deploy to Cloud Run
gcloud run deploy ${SERVICE} \
  --image ${IMAGE} \
  --region ${REGION} \
  --platform managed \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=5 \
  --memory=256Mi \
  --cpu=1 \
  --concurrency=80 \
  --timeout=30 \
  --set-env-vars="GOOGLE_CLIENT_ID_WEB=YOUR_WEB_CLIENT_ID,GOOGLE_CLIENT_ID_ANDROID=YOUR_ANDROID_CLIENT_ID,ALLOWED_ORIGINS=*" \
  --set-env-vars="GOOGLE_CLIENT_SECRET_WEB=YOUR_WEB_CLIENT_SECRET"
```

(If you split env vars over multiple `--set-env-vars` flags, each flag
replaces the whole map — use one flag with comma-separated `KEY=VAL`
pairs, or combine into a single flag as shown.)

---

## Build & deploy — option B (local Docker → Artifact Registry → Cloud Run)

Use this if you want to build on your own machine (faster iteration, or
no Cloud Build quota):

```bash
cd /app/cloud-run/auth-service

PROJECT_ID=$(gcloud config get-value project)
SERVICE=stellartimelock-auth
REGION=us-east5
IMAGE=us-east5-docker.pkg.dev/${PROJECT_ID}/auth-repo/${SERVICE}:latest

# 1. Build locally (linux/amd64 required for Cloud Run)
docker build --platform linux/amd64 -t ${IMAGE} .

# 2. Push to Artifact Registry
docker push ${IMAGE}

# 3. Deploy
gcloud run deploy ${SERVICE} \
  --image ${IMAGE} \
  --region ${REGION} \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars="GOOGLE_CLIENT_ID_WEB=YOUR_WEB_CLIENT_ID,GOOGLE_CLIENT_ID_ANDROID=YOUR_ANDROID_CLIENT_ID,ALLOWED_ORIGINS=*" \
  --set-env-vars="GOOGLE_CLIENT_SECRET_WEB=YOUR_WEB_CLIENT_SECRET"
```

---

## Recommended: keep the secret in Secret Manager

```bash
# Create the secret (first time only)
echo -n "GOCSPX-your-real-secret-value" | \
  gcloud secrets create google-client-secret-web --data-file=-

# Grant the Cloud Run runtime SA read access
RUNTIME_SA=$(gcloud run services describe stellartimelock-auth \
  --region=us-east5 --format="value(spec.template.spec.serviceAccountName)")

# (First deploy uses the default compute SA; capture whatever the above returns)
gcloud secrets add-iam-policy-binding google-client-secret-web \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/secretmanager.secretAccessor"

# Re-deploy, mounting the secret as an env var
gcloud run deploy stellartimelock-auth \
  --image ${IMAGE} \
  --region us-east5 \
  --update-secrets=GOOGLE_CLIENT_SECRET_WEB=google-client-secret-web:latest
```

---

## Grab the service URL for the frontend

```bash
gcloud run services describe stellartimelock-auth \
  --region=us-east5 \
  --format="value(status.url)"
# → https://stellartimelock-auth-XXXXX-uk.a.run.app
```

Put this URL into `/app/frontend/.env` as:

```
EXPO_PUBLIC_AUTH_SERVICE_URL=https://stellartimelock-auth-XXXXX-uk.a.run.app
```

…and restart the Expo dev server.

---

## Local smoke test (optional)

```bash
cd /app/cloud-run/auth-service
pip install -r requirements.txt
GOOGLE_CLIENT_ID_WEB=xxxxx GOOGLE_CLIENT_SECRET_WEB=yyyyy \
  GOOGLE_CLIENT_ID_ANDROID=zzzz \
  uvicorn main:app --port 8080 --reload

curl http://localhost:8080/healthz
# → {"status":"ok","service":"stellartimelock-auth"}
```

---

## Rotating the client secret

1. In Google Cloud Console → Credentials → your Web OAuth client → **Reset secret**.
2. Update Secret Manager: `gcloud secrets versions add google-client-secret-web --data-file=-`.
3. `gcloud run services update stellartimelock-auth --region=us-east5 --update-secrets=GOOGLE_CLIENT_SECRET_WEB=google-client-secret-web:latest`.

Cloud Run rolls the new revision with zero downtime; existing user
tokens keep working because Google only checks the secret at
auth-code exchange time, not on every API call.
