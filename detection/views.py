import os
import pickle
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from .forms import RegisterForm
from .featureExtractor import featureExtraction
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from .models import SecurityProfile
from .models import DetectionLog
from django.http import JsonResponse
from groq import Groq
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------ Paths ------------------
PHISH_MODEL_PATH = os.path.join(BASE_DIR, 'model', 'phishingdetection')
SQLI_DIR = os.path.join(BASE_DIR, 'model', 'sql_injection')

# Lazy cache for models
_lazy = {
    'phish_model': None,
    'phish_error': None,
    'rf_bundle': None,
    'lr_bundle': None,
    'sqli_error': None,
}


def index(request):
    return render(request, 'index.html')

def _load_pycaret_model():
    if _lazy['phish_model'] is not None or _lazy['phish_error'] is not None:
        return
    try:
        from pycaret.classification import load_model
        _lazy['phish_model'] = load_model(PHISH_MODEL_PATH)
        _lazy['phish_error'] = None
    except Exception as e:
        _lazy['phish_model'] = None
        _lazy['phish_error'] = str(e)

# ===================================================
# 🔹 Load SQL Injection models (new .pkl bundles)
# ===================================================
def _load_sqli_models():
    if _lazy['rf_bundle'] is not None or _lazy['sqli_error'] is not None:
        return
    try:
        with open(os.path.join(SQLI_DIR, 'sqli_random_forest.pkl'), 'rb') as f:
            _lazy['rf_bundle'] = pickle.load(f)
        with open(os.path.join(SQLI_DIR, 'sqli_logistic_regression.pkl'), 'rb') as f:
            _lazy['lr_bundle'] = pickle.load(f)
        _lazy['sqli_error'] = None
    except Exception as e:
        _lazy['rf_bundle'] = None
        _lazy['lr_bundle'] = None
        _lazy['sqli_error'] = str(e)

# ===================================================
# 🔹 Auth Views
# ===================================================
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            login(request, user)
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

from .models import SecurityProfile



def login_view(request):

    form = AuthenticationForm(request, data=request.POST or None)

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        print("\n==============================")
        print("LOGIN ATTEMPT")
        print("Username:", username)
        print("Password:", password)

        # ---------------------------------------
        # Step 1: SQL Injection detection
        # ---------------------------------------
        rf_result = detect_sqli_with_rf(password)
        ip = request.META.get('REMOTE_ADDR')

        is_malicious = False

        if rf_result and "label" in rf_result:
            if "Malicious" in rf_result["label"]:
                is_malicious = True

        # ---------------------------------------
        # Step 2: Get User
        # ---------------------------------------
        try:
            user = User.objects.get(username=username)

            profile, created = SecurityProfile.objects.get_or_create(user=user)

        except User.DoesNotExist:
            messages.error(request, "Invalid username or password")
            return render(request, "login.html", {"form": form})

        # ---------------------------------------
        # Save detection log
        # ---------------------------------------
        DetectionLog.objects.create(
            user=user,
            ip_address=ip,
            input_query=password,
            prediction=rf_result["label"],
            risk_level=rf_result.get("risk", "Low")
        )

        # ---------------------------------------
        # Step 3: Handle SQL Injection
        # ---------------------------------------
        if is_malicious:

            print("⚠ MALICIOUS SQL COMMAND DETECTED")

            profile.malicious_attempts += 1
            profile.save()

            attempts = profile.malicious_attempts

            print("Malicious attempts:", attempts)

            # 1st or 2nd attempt
            if attempts < 3:

                messages.error(
                    request,
                    f"Malicious SQL command detected ({attempts}/5)"
                )

                return render(request, "login.html", {"form": form})

            # ---------------------------------------
            # 3rd attempt → send verification email
            # ---------------------------------------
            if attempts == 3:

                token = get_random_string(64)

                profile.verification_token = token
                profile.is_verified = False
                profile.save()

                verification_link = request.build_absolute_uri(f"/verify/{token}/")

                send_mail(
                    subject="Security Alert: SQL Injection Detected",
                    message=(
                        "You entered a malicious SQL Injection command.\n\n"
                        "Please verify it is you by clicking the link below:\n\n"
                        f"{verification_link}"
                    ),
                    from_email=None,
                    recipient_list=[user.email],
                    fail_silently=False,
                )

                messages.error(
                    request,
                    "⚠ Malicious activity detected. Verification email sent."
                )

                return render(request, "login.html", {"form": form})

            # ---------------------------------------
            # 4th attempt
            # ---------------------------------------
            if attempts == 4:

                messages.error(
                    request,
                    "⚠ Final warning! Next malicious attempt will block your IP."
                )

                return render(request, "login.html", {"form": form})

            # ---------------------------------------
            # 5th attempt → AUTO BLOCK IP
            # ---------------------------------------
            if attempts >= 5:

                from .models import BlockedIP

                BlockedIP.objects.update_or_create(
                    ip_address=ip,
                    defaults={
                        "reason": "Multiple SQL Injection Attempts",
                        "is_active": True
                    }
                )

                print("🚫 IP BLOCKED:", ip)

                return redirect("access_denied")

        # ---------------------------------------
        # Step 4: Normal Login
        # ---------------------------------------
        if user.check_password(password):

            if not profile.is_verified:

                messages.error(request, "Please verify your identity via email")
                return render(request, "login.html", {"form": form})

            # Reset malicious attempts
            profile.malicious_attempts = 0
            profile.save()

            login(request, user)

            return redirect("predict")

        # ---------------------------------------
        # Wrong password
        # ---------------------------------------
        messages.error(request, "Invalid username or password")

    return render(request, "login.html", {"form": form})

from django.shortcuts import get_object_or_404

from django.db.models import Count
from .models import DetectionLog

def history_view(request):

    if not request.user.is_authenticated:
        return redirect("login")

    logs = DetectionLog.objects.filter(user=request.user).order_by("-created_at")

    total_requests = logs.count()

    total_attacks = logs.filter(prediction__icontains="Malicious").count()

    normal_requests = logs.filter(prediction__icontains="Benign").count()

    context = {
        "logs": logs,
        "total_requests": total_requests,
        "total_attacks": total_attacks,
        "normal_requests": normal_requests
    }

    return render(request, "history.html", context)

def verify_user(request, token):
    profile = get_object_or_404(SecurityProfile, verification_token=token)

    profile.is_verified = True
    profile.malicious_attempts = 0
    profile.verification_token = None
    profile.save()

    messages.success(
        request,
        "Verification successful. Please login again."
    )
    return redirect("login")

def logout_view(request):
    logout(request)
    return redirect('login')

# ===================================================
# 🔹 Phishing Detection
# ===================================================
def detect_phishing(url):
    _load_pycaret_model()
    if _lazy['phish_model'] is None:
        return {'label': 'ModelLoadError', 'score': 0.0, 'error': _lazy['phish_error']}
    try:
        from pycaret.classification import predict_model
        X = featureExtraction(url)
        result = predict_model(_lazy['phish_model'], data=X)

        lbl_raw = str(result['prediction_label'][0]).strip().lower()
        score = float(result['prediction_score'][0]) * 100.0 if 'prediction_score' in result and result['prediction_score'].notnull().any() else 0.0

        if lbl_raw in ['1', 'malicious', 'phish']:
            label = "🔴 Malicious URL"
        elif lbl_raw in ['0', 'benign', 'safe']:
            label = "🟢 Safe URL"
        else:
            label = lbl_raw

        return {'label': label, 'score': score}

    except Exception as e:
        return {'label': 'Error', 'score': 0.0, 'error': str(e)}

# ===================================================
# 🔹 SQL Injection Detection (RandomForest + LogisticRegression)
# ===================================================
def detect_sqli_with_rf(text):
    print("---- SQLi Detection Start ----")
    print("Input text:", text)

    _load_sqli_models()

    if not _lazy['rf_bundle']:
        print("Model load error:", _lazy['sqli_error'])
        return {'label': 'ModelLoadError', 'score': 0.0, 'error': _lazy['sqli_error']}

    try:
        vec = _lazy['rf_bundle']['vectorizer']
        model = _lazy['rf_bundle']['model']
        le = _lazy['rf_bundle']['label_encoder']

        X = vec.transform([text])
        print("Vectorized input shape:", X.shape)

        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0]

        print("Raw prediction:", pred)
        print("Prediction probabilities:", proba)

        label = le.inverse_transform([pred])[0]
        print("Decoded label:", label)

        label_pretty = "🛑 Malicious (SQLi)" if label.lower() == "malicious" else "🟢 Benign"

        print("Pretty label:", label_pretty)
        print("---- SQLi Detection End ----")

        if label.lower() == "malicious":

            if proba[pred] > 0.9:
                risk = "High"
            elif proba[pred] > 0.6:
                risk = "Medium"
            else:
                risk = "Low"

            label_pretty = "🛑 Malicious (SQLi)"

        else:

            label_pretty = "🟢 Benign"
            risk = "Low"

        return {
            'label': label_pretty,
            'score': round(proba[pred] * 100, 2),
            'risk': risk
        }

    except Exception as e:
        print("SQLI ERROR:", str(e))
        return {'label': 'Error', 'score': 0.0, 'error': str(e)}

def detect_sqli_with_lr(text):
    _load_sqli_models()
    if not _lazy['lr_bundle']:
        return {'label': 'ModelLoadError', 'score': 0.0, 'error': _lazy['sqli_error']}
    try:
        vec = _lazy['lr_bundle']['vectorizer']
        model = _lazy['lr_bundle']['model']
        le = _lazy['lr_bundle']['label_encoder']

        X = vec.transform([text])
        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        label = le.inverse_transform([pred])[0]
        label_pretty = "🛑 Malicious (SQLi)" if label.lower() == "malicious" else "🟢 Benign"
        return {'label': label_pretty, 'score': round(proba[pred] * 100, 2)}
    except Exception as e:
        return {'label': 'Error', 'score': 0.0, 'error': str(e)}

# ===================================================
#  Prediction Page
# ===================================================
def predict_view(request):
    if not request.user.is_authenticated:
        return redirect('login')

    context = {'phishing': None, 'sqli_rf': None, 'sqli_lr': None}

    if request.method == 'POST':
        if 'check_phishing' in request.POST:
            url = request.POST.get('phish_url', '').strip()
            if not url:
                context['phishing'] = {'label': 'Error', 'error': 'Please enter a URL.'}
            else:
                context['phishing'] = detect_phishing(url)

        if 'check_sqli' in request.POST:
            text = request.POST.get('sqli_text', '').strip()
            if not text:
                err = {'label': 'Error', 'error': 'Please enter input to analyze.'}
                context['sqli_rf'] = err
                context['sqli_lr'] = err
            else:
                context['sqli_rf'] = detect_sqli_with_rf(text)
                context['sqli_lr'] = detect_sqli_with_lr(text)

    return render(request, 'predict.html', context)

def delete_log(request, id):

    log = DetectionLog.objects.get(id=id)

    log.delete()

    return redirect("history")

import csv
from django.http import HttpResponse

def download_logs(request):

    logs = DetectionLog.objects.filter(user=request.user)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="attack_logs.csv"'

    writer = csv.writer(response)

    writer.writerow(["IP Address","Timestamp","Query","Prediction","Risk"])

    for log in logs:

        writer.writerow([
            log.ip_address,
            log.created_at,
            log.input_query,
            log.prediction,
            log.risk_level
        ])

    return response

import os
from django.views.decorators.csrf import csrf_exempt
from groq import Groq

client = Groq(api_key="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")


def chatbot_page(request):

    if not request.user.is_authenticated:
        return redirect("login")

    return render(request, "chatbot.html")


@csrf_exempt
def chatbot_api(request):

    if request.method == "POST":

        user_message = request.POST.get("message")

        try:

            chat_completion = client.chat.completions.create(

                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity assistant helping users understand SQL injection attacks and web security."
                    },
                    {
                        "role": "user",
                        "content": user_message
                    }
                ],

                model="llama-3.1-8b-instant"

            )

            reply = chat_completion.choices[0].message.content

        except Exception as e:

            reply = "Error: " + str(e)

        return JsonResponse({"response": reply})
    

from .models import BlockedIP


def block_ip(request, ip):

    BlockedIP.objects.update_or_create(
        ip_address=ip,
        defaults={
            "reason": "SQL Injection Attacks",
            "is_active": True
        }
    )

    messages.success(request, f"{ip} blocked successfully")

    return redirect("history")


def unblock_ip(request, ip):

    try:
        blocked = BlockedIP.objects.get(ip_address=ip)

        blocked.is_active = False

        blocked.save()

        messages.success(request, f"{ip} unblocked")

    except BlockedIP.DoesNotExist:
        pass

    return redirect("history")


def access_denied(request):

    ip = request.META.get("REMOTE_ADDR")

    return render(request, "access_denied.html", {"ip": ip})