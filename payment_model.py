#======================================
#            >>>>PAYMENT MODEL<<<<
#======================================

@app.route('/payment')
def payment():
    return render_template('pay.html', user=current_user)

# ----------------------------------------------------------------------

@app.route('/api/pay', methods=['POST'])
def pay():
    data = request.json
    phone = data.get('phone')
    amount = int(data.get('amount'))

    if not phone or not amount:
        return jsonify({"success": False, "message": "Phone or amount missing"}), 400

    # Convert phone to Safaricom format: 2547XXXXXXX
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone.replace("+", "")

    # Save pending payment
    pending = Payment(
        user_id=current_user.id,
        phone=phone,
        amount=amount,
        status="Pending",
        timestamp=datetime.utcnow()
    )
    db.session.add(pending)
    db.session.commit()

    # M-Pesa credentials
    consumer_key = os.getenv("MPESA_CONSUMER_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET")
    passkey = os.getenv("MPESA_PASSKEY")
    business_short_code = "174379"  # actual shortcode
    callback_url = "https://viewstream-1.onrender.com/callback"

    # Choose environment: sandbox or live
    is_live = os.getenv("MPESA_ENV", "sandbox").lower() == "live"
    base_url = "https://api.safaricom.co.ke" if is_live else "https://sandbox.safaricom.co.ke"

    # Step 1: Generate access token
    try:
        auth_response = requests.get(
            f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
            auth=(consumer_key, consumer_secret)
        )
        print("Token response:", auth_response.text)
        auth_response.raise_for_status()
        access_token = auth_response.json().get("access_token")
    except Exception as e:
        return jsonify({"success": False, "message": f"Token error: {str(e)}"}), 500

    # Step 2: Build STK push request
    timestamp = (datetime.now() + timedelta(hours=3)).strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((business_short_code + passkey + timestamp).encode()).decode()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": business_short_code,
        "PhoneNumber": phone,
        "CallBackURL": callback_url,
        "AccountReference": "Ref001",
        "TransactionDesc": "VIP Subscription"
    }

    # Step 3: Send STK Push
    try:
        response = requests.post(
            f"{base_url}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers
        )
        print("STK Push response:", response.text)
        response.raise_for_status()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"Push error: {str(e)}"}), 500

# ------------------------------------------------------------------------
@app.route('/callback', methods=['POST'])
def callback():
    data = request.get_json()
    print("Callback Received:", data)

    try:
        callback_data = data['Body']['stkCallback']
        result_code = callback_data['ResultCode']
        result_desc = callback_data['ResultDesc']

        if result_code == 0:
            metadata = callback_data['CallbackMetadata']['Item']
            phone_number = None
            receipt = None

            for item in metadata:
                if item['Name'] == 'PhoneNumber':
                    phone_number = str(item['Value'])
                elif item['Name'] == 'MpesaReceiptNumber':
                    receipt = item['Value']

            payment = Payment.query.filter_by(phone=phone_number, status="Pending").order_by(Payment.timestamp.desc()).first()

            if payment:
                payment.status = "Success"
                payment.mpesa_receipt = receipt
                db.session.commit()

                user = User.query.get(payment.user_id)
                if user:
                    user.plus_type = "paid"
                    hours_to_add = int(payment.amount)
                    now = datetime.utcnow()
                    if user.plus_expires_at and user.plus_expires_at > now:
                        user.plus_expires_at += timedelta(hours=hours_to_add)
                    else:
                        user.plus_expires_at = now + timedelta(hours=hours_to_add)
                    db.session.commit()

            print("Payment verified and Plus access granted.")
            return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})

        else:
            print("Payment failed:", result_desc)
            return jsonify({"ResultCode": 0, "ResultDesc": "Failed transaction"})

    except Exception as e:
        print("Callback processing error:", str(e))
        return jsonify({"ResultCode": 1, "ResultDesc": "Error processing callback"})