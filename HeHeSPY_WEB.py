import ipaddress
import os
import base64
import random
import time
from flask import Flask, send_from_directory, request, abort, send_file, render_template, make_response, jsonify, redirect, Response, url_for, session, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from requests import get
from threading import Thread
import requests

import HeHeSPY as GPCM


from flask import Flask, session
from flask_session import Session
import redis

global ip_whitelist
global ip_blacklist

ip_whitelist = {"192.168.1.0/24", "127.0.0.1","0.0.0.0/0"} #for allowing all addresses its 0.0.0.0/0
ip_blacklist = {"0.0.0.0"} # for everyone its 0.0.0.0/0
Main_Key = "HEYYOUSTOPTHERE"

global ses_count
ses_count = 0


app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per minute", "8 per second"],
    storage_uri="memory://",
    # Redis
    #storage_uri="redis://localhost:6379",
    # Redis cluster
    # storage_uri="redis+cluster://localhost:7000,localhost:7001,localhost:70002",
    # Memcached
    # storage_uri="memcached://localhost:11211",
    # Memcached Cluster
    # storage_uri="memcached://localhost:11211,localhost:11212,localhost:11213",
    # MongoDB
    # storage_uri="mongodb://localhost:27017",
    # Etcd
    # storage_uri="etcd://localhost:2379",
    strategy="fixed-window", # or "moving-window"
)


app.secret_key = "REDACTEDREDACTEDREDACTED"

# Configure session to use Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'HeHeSPY'  # Change this to a unique prefix
app.config['SESSION_REDIS'] = redis.StrictRedis(host='192.168.1.153', port=6379, db=0)

# Initialize the extension
Session(app)

# Define the path to your webroot directory
webroot_dir = "webroot"




@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), fullscreen=(self), payment=()'
    response.headers['Content-Security-Policy'] = "default-src *; script-src * 'unsafe-inline'; style-src * 'unsafe-inline'; img-src * 'unsafe-inline'; connect-src * 'unsafe-inline'; font-src * 'unsafe-inline'; object-src * 'unsafe-inline'; media-src * 'unsafe-inline'; frame-src * 'unsafe-inline'; worker-src * 'unsafe-inline'"
    return response




@app.before_request
def limit_remote_addr():
    client_ip = request.remote_addr
    blocked_ip_doc = f'''
<!DOCTYPE html>
<html lang="en" class="flow-text" style="
    color-scheme: light dark !important;
">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeHeSPY Server</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css">
  <style>
    body {{
      background-color: #5f5f5f55 !important;
    }}
    .container {{
      margin-top: 50px;
    }}
    .card-panel {{
      padding: 20px;
    }}
  </style>
</head>
<body>

<div class="container">
  <div class="row">
    <div class="col s12 m8 offset-m2">
      <div class="card-panel">
        <h4 class="center-align">HeHeSPY Server</h4>
        <p>
          We're sorry, but you are not authorized to connect to this private server. Your IP address is not whitelisted.
        </p>
        <p>
          If you believe this is an error, please contact the server administrator for further assistance.
        </p>
      </div>
    </div>
  </div>
</div>

<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
</body>
</html>

'''
    banned_ip_doc = f'''
<!DOCTYPE html>
<html lang="en" class="flow-text" style="
    color-scheme: light dark !important;
">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeHeSPY Server</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css">
  <style>
    body {{
      background-color: #5f5f5f55 !important;
    }}
    .container {{
      margin-top: 50px;
    }}
    .card-panel {{
      padding: 20px;
    }}
  </style>
</head>
<body>

<div class="container">
  <div class="row">
    <div class="col s12 m8 offset-m2">
      <div class="card-panel">
        <h4 class="center-align">HeHeSPY Server</h4>
        <p class="red">
          We're sorry, but you are not authorized to connect to this private server. Your IP address is Banned.
        </p>
        <p>
          If you believe this is an error, please contact the server administrator for further assistance.
        </p>
      </div>
    </div>
  </div>
</div>

<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
</body>
</html>

'''

    secure_pages = ['/signup','/signup.html']

    if is_ip_banned(client_ip):
        return banned_ip_doc, 403
    elif not is_ip_allowed(client_ip):
        return blocked_ip_doc, 403   
        #abort(418)  # Forbidden
    else:
        if "conntest.nintendowifi.net" in request.url_root:
            print("nintendo device connected")
            
            response = jsonify({"message": "NINTENDO WIFI TEST RESPONSE"})
            response.headers['X-Organization'] = 'Nintendo'
            return response  
        
    if request.path in secure_pages:
        return """
    <html class="flow-text" style="color-scheme: light dark !important; background-color: #5f5f5f55 !important;">
    <head>
    <title>HeHeSPY Security</title>
    <meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="format-detection" content="telephone=no">
	<meta name="viewport" content="width = device-width, height = device-height, user-scalable = no">
	
	<!--Import Google Icon Font-->
      <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
      <!--Import materialize.css-->
      <link type="text/css" rel="stylesheet" href="css/signup/materialize.min.css" media="screen,projection">
	  <script type="text/javascript" src="js/materialize.min.js"></script>
	        <!--Let browser know website is optimized for mobile-->
      <meta name="viewport" content="width=device-width">
    </head>
    <p style="color:red;">HTTP Error - 403 FORBIDDEN | HTTPS ONLY</p><div class="red white-text"><p>you are seeing this message because you are probably about to send sensitive information over to HeHeSPY Servers</p><p>please change to https or press the button below</p></div>
    <script>
    function secureU(){
    const svr = `${document.location}`;
    const repsvr = svr.replace("http://", "https://");

    document.location=repsvr;
    }
    </script>    
    <p class="white-text">You need to use secure https for this part of HeHeSPY, use this button to redirect</p> <div class="center"><button onclick="secureU()" class="waves-effect waves-light btn-large"><i class="material-icons left">https</i>TAKE ME TO THE SECURE SIDE!!!!</button></div>
    </html>
    """, 403

"""
@app.before_request
def motd_redirector():
    print(request.host_url)
    if "http://motd.gamespy.com/" in request.host_url:
        url = 'http://127.0.0.1:28900' + request.path
        headers = {key: value for (key, value) in request.headers.items()}
        data = request.get_data()
        
        try:
            response = requests.get(url, data=data, headers=headers, timeout=15)  # Set timeout here
            return Response(response.content, response.status_code, headers)
        except requests.exceptions.RequestException as e:
            # Handle any request exceptions here
            return Response("Error: " + str(e), status=500)
"""

@app.before_request
def general_redirector():
    print(f"Got {request.host_url}")
    RedirList = ['motd', 'gpcm', 'gpsp', 'chat']
    for i in RedirList:
        if f"://{i}.gamespy.com" in request.host_url:
            return f"""<big>the <b>{i}</b> subdomain is not for normal http/https use. <br> you may have to use its respectable port to connect to the <b>{i}</b> server</big>""",500
        


#@app.errorhandler(404)
#def page_not_found(e):
#    return f'<h1 style="font-size: 100%">{e}</h1>' , 404


@app.route('/set_email', methods=['GET', 'POST'])
def set_email():
    if request.method == 'POST':
        # Save the form data to the session object
        session['email'] = request.form['email_address']
        return redirect(url_for('userlogin'))

    return """
        <form method="post">
            <label for="email">Enter your email address:</label>
            <input type="email" id="email" name="email_address" required />
            <button type="submit">Submit</button
        </form>
        """


@app.route('/get_email')
def get_email():
    return render_template_string("""
            {% if session['email'] %}
                <h1>Welcome {{ session['email'] }}!</h1>
            {% else %}
                <h1>Welcome! Please enter your email <a href="{{ url_for('set_email') }}">here.</a></h1>
            {% endif %}
        """)

@app.route('/login')
def userlogin():

    return render_template_string("""
            hi
            {% if session['email'] %}
                <h1>Welcome {{ session['email'] }}!</h1>
            {% else %}
                <h1>Welcome! Please enter your email <a href="{{ url_for('set_email') }}">here.</a></h1>
            {% endif %}
        """)

@app.route('/delete_email')
def delete_email():
    # Clear the email stored in the session object
    session.pop('email', default=None)
    return '<h1>Session deleted!</h1>'

@app.route("/ka/final/")
def status_response():
    return "//ka////final//"  
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uniquenickname = request.form.get('uniquenickname')
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        password = request.form.get('password')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        birthdate = request.form.get('birthdate')
        namespaceid = request.form.get('namespaceid')
        partnerid = request.form.get('partnerid')
        emailconfirm = request.form.get('emailconfirm')

        # You can process the form data here and create user accounts
        # For demonstration, we'll just print the form data
        GPCM.web_create_user(uniquenickname,nickname,email,password,firstname,lastname,namespaceid,partnerid,emailconfirm)

        print(f'Unique Nickname: {uniquenickname}')
        print(f'Nickname: {nickname}')
        print(f'Email: {email}')
        print(f'Password: {password}')
        print(f'First Name: {firstname}')
        print(f'Last Name: {lastname}')
        print(f'BirthDate: {birthdate}')
        print(f'Namespace ID: {namespaceid}')
        print(f'Partner ID: {partnerid}')
        print(f'email confirmation: {emailconfirm}')

    full_path = os.path.join(webroot_dir, "signup.html")
    if os.path.exists(full_path):
        if os.path.isdir(full_path):
            # If it's a directory, try to serve the index.html file
            index_path = os.path.join(full_path, 'index.html')
            if os.path.exists(index_path):
                return send_file(index_path)
            abort(404)  # No index file found
        else:
            return send_file(full_path)
    abort(404)  # File or directory not found

@app.route('/api/', defaults={'action': None}, methods=['GET', 'POST'])
@app.route('/api/<action>', methods=['GET', 'POST'])
@limiter.limit("50 per minute", methods=['GET', 'POST','DELETE','PUT','PATCH'])
def apiadding(action):
    global ses_count
    if request.method == 'POST':
        print(f'ACTION: {action}')
        if action == "sessionadded":
            if request.headers.get("X-Authorization") == Main_Key:
                ses_count += 1
                print(f"ses: {ses_count}")
                return "success", 200
            else:
                abort(401)
        elif action == "sessionremoved":
            if request.headers.get("X-Authorization") == Main_Key:
                if ses_count > 0:
                  ses_count -= 1
                else:
                  print(f"ses count was already at the lowest value: {ses_count}")
                print(f"ses: {ses_count}")
                return "success", 200
            else:
                abort(401)
        elif action == "sessionreset":
            if request.headers.get("X-Authorization") == Main_Key:
                if ses_count > 0:
                  ses_count = 0
                else:
                  print(f"ses count was already at the lowest value: {ses_count}")
                print(f"ses: {ses_count}")
                return "success", 200
            else:
                abort(401)
        else:
            #if Not any of these actions then byeee
            abort(404)
    elif request.method == 'GET':
        print(f'GET ACTION: {action}')
        data = {
        "AccountsMade" : GPCM.count_users(),
        "ConnectedClients" : ses_count       
        }
        return jsonify(data)
    
    else:
        #if not post or get then whatever
        abort(405)

@app.route('/')
def serve_index():
    full_path = os.path.join(webroot_dir, "index.html")
    if os.path.exists(full_path):
        return send_from_directory(webroot_dir, "index.html")
    abort(404)  # File or directory not found
    
@app.route('/software/waypages/installed/userroom_intro')
def serve_userroom():
    full_path = os.path.join(webroot_dir, "software/waypages/installed/userroom_intro.shtml")
    if os.path.exists(full_path):
        return send_from_directory(webroot_dir, "software/waypages/installed/userroom_intro.shtml")
    abort(404)  # File or directory not found
    
@app.route('/http://www.gamespyarcade.com/software/arcadedaily/_img/index/btn_techsupport.gif HTTP/1.1')
def serve_img_btnts():
    full_path = os.path.join(webroot_dir, "software/arcadedaily/_img/index/btn_techsupport.gif")
    if os.path.exists(full_path):
        return send_from_directory(webroot_dir, "software/arcadedaily/_img/index/btn_techsupport.gif")
    abort(404)  # File or directory not found
    
@app.route('/SakeStorageServer/StorageServer.asmx', methods = ['POST'])
def serve_sakestorage():  
    servexml = """
<?xml version='1.0' encoding='utf8'?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://gamespy.net/sake/"><SOAP-ENV:Body><ns1:GetMyRecordsResponse><ns1:GetMyRecordsResult>LoginTicketInvalid</ns1:GetMyRecordsResult></ns1:GetMyRecordsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
    return Response(servexml, mimetype="application/xml")
    
@app.route('/AuthService/AuthService.asmx', methods = ['POST'])
def serve_sakelogin():
    servexml = """<?xml version='1.0' encoding='utf8'?>
<SOAP-ENV:Envelope
	xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:ns1="http://gamespy.net/AuthService/">
	<SOAP-ENV:Body>
		<ns1:LoginProfileResult>
			<ns1:responseCode>7</ns1:responseCode>
		</ns1:LoginProfileResult>
	</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""  
    oservexml = """
<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:aut="http://gamespy.net/AuthService/">
    <soapenv:Body>
        <aut:LoginUniqueNick>
            <aut:uniquenick>kai</aut:uniquenick>
            <aut:partnercode>0</aut:partnercode>
            <aut:namespaceid>64</aut:namespaceid>
            <aut:password>
                <aut:Value>af70c203ff1df6c5b85ea666975b0c7bf35828f5ddbcc4feb9ef9971ad0c6adff4012063e061246907124c230d8cd2ced1e8b7abc473604edc28fba41aaa1f7919c66ace4bd5838cc1e45606e9a9a281d78ceab2d2b34a0f04912dfad97c17105baa714652996f970a595f674df03717e3c09eae242661f3c891702566223b5a</aut:Value>
            </aut:password>
        </aut:LoginUniqueNick>
    </soapenv:Body>
</soapenv:Envelope>"""
    return Response(servexml, mimetype="application/xml")

@app.route('/ASP/getplayerinfo.aspx')
def bf2_gpi():  
    return """
O
H	asof
D	1233666565
H	pid	nick	ktm-1	vtm-3	wtm-0	mtm-4	
D	143414126	-=EA=-Vex	74162	36658	40273	40798	
$	83	$
"""

@app.route('/ASP/getawardsinfo.aspx')
def bf2_gai():  
    return """
O
H	pid	asof
D	43861616	1321461705
H	award	level	when	first
D	1031105	1	1124047874	0
D	1031113	1	1120847831	0
D	1031115	1	1121220196	0
D	1031119	1	1119898482	0
D	1031119	2	1129236689	0
D	1031120	1	1119999271	0
D	1031121	1	1120242869	0
D	1190304	1	1120428059	0
D	1190601	1	1122483300	0
D	1191819	1	1122769961	0
D	1191819	2	1128550558	0
D	1220118	1	1119583630	0
D	1220803	1	1119897005	0
D	1260602	1	1139107151	0
D	1261119	1000	1142017780	0
D	2051902	1000	1710020599	1119999271
D	2051907	1000	1710020599	1120069867
D	2051919	1000	1710020599	1120087402
D	2191608	1000	1710020599	1121287954
D	3150914	1000	1120158038	0
D	3151920	1000	1121021268	0
D	3190605	1000	1128470984	0
D	3191305	1000	1128449632	0
D	3211305	1000	1119999271	0
D	3240102	1000	1139107151	0
D	3240301	1000	1123719721	0
$	605	$
"""

@app.route('/ASP/getleaderboard.aspx')
def bf2_glb():  
    return """
<html><body>




 <style>td { font-family: verdana; font-size: 8pt; }</style><table border="1"><tbody><tr bgcolor="silver">	<td>44</td>	<td>Type</td>	<td>ID</td>	<td>Alias</td>	<td>View</td>	<td>Proc</td>	<td>Size</td>	<td>LastUpdate</td></tr><tr>	<td>1</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=army&amp;id=0&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">army</a></td>	<td>0</td>	<td>USA</td>	<td>dbo.view_Leaders_Army</td>	<td>get_leaders_army</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>2</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=army&amp;id=1&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">army</a></td>	<td>1</td>	<td>MEC</td>	<td>dbo.view_Leaders_Army</td>	<td>get_leaders_army</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>3</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=army&amp;id=2&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">army</a></td>	<td>2</td>	<td>Chinese</td>	<td>dbo.view_Leaders_Army</td>	<td>get_leaders_army</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>4</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=0&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>0</td>	<td>AntiTank</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>5</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=1&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>1</td>	<td>Assault</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>6</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=2&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>2</td>	<td>Engineer</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>7</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=3&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>3</td>	<td>Medic</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>8</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=4&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>4</td>	<td>SpecOps</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>9</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=5&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>5</td>	<td>Support</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>10</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=kit&amp;id=6&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">kit</a></td>	<td>6</td>	<td>Sniper</td>	<td>dbo.view_Leaders_Kit</td>	<td>get_leaders_kit</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>11</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=0&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>0</td>	<td>KubraDam</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>12</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=1&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>1</td>	<td>MashtuurCity</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>13</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=100&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>100</td>	<td>DaqingOilFields</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>14</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=101&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>101</td>	<td>DalianPlant</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>15</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=102&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>102</td>	<td>DragonValley</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>16</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=103&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>103</td>	<td>TheGlowingPass</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>17</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=104&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>104</td>	<td>HinganHills</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>18</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=105&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>105</td>	<td>SonghuaStalemate</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>19</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=3&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>3</td>	<td>CleanSweep</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>20</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=4&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>4</td>	<td>StrikeAtKarkand</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>21</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=5&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>5</td>	<td>SharqiStrait</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>22</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=map&amp;id=6&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">map</a></td>	<td>6</td>	<td>GulfOfOman</td>	<td>dbo.view_Leaders_Maps</td>	<td>get_leaders_maps</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>23</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=risingstar&amp;id=&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">risingstar</a></td>	<td></td>	<td>RisingStar</td>	<td>dbo.view_Leaders_RisingStar</td>	<td>get_leaders_risingstar</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>24</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=score&amp;id=combat&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">score</a></td>	<td>combat</td>	<td>Combat</td>	<td>dbo.view_Leaders_Score_Combat</td>	<td>get_leaders_score_combat</td>	<td>136063</td>	<td>6/14/2013 7:04:12 PM</td></tr><tr>	<td>25</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=score&amp;id=commander&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">score</a></td>	<td>commander</td>	<td>Commander</td>	<td>dbo.view_Leaders_Score_Commander</td>	<td>get_leaders_score_commander</td>	<td>136063</td>	<td>6/14/2013 7:04:13 PM</td></tr><tr>	<td>26</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=score&amp;id=overall&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">score</a></td>	<td>overall</td>	<td>Overall</td>	<td>dbo.view_Leaders_Score_Overall</td>	<td>get_leaders_score_overall</td>	<td>136063</td>	<td>6/14/2013 7:04:11 PM</td></tr><tr>	<td>27</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=score&amp;id=team&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">score</a></td>	<td>team</td>	<td>Team</td>	<td>dbo.view_Leaders_Score_Team</td>	<td>get_leaders_score_team</td>	<td>136063</td>	<td>6/14/2013 7:04:15 PM</td></tr><tr>	<td>28</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=timeplayed&amp;id=&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">timeplayed</a></td>	<td></td>	<td>TimePlayed</td>	<td>dbo.view_Leaders_Time</td>	<td>get_leaders_time</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>29</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=0&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>0</td>	<td>Armor</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>30</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=1&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>1</td>	<td>Aviator</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>31</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=2&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>2</td>	<td>AirDefense</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>32</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=3&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>3</td>	<td>Helicopter</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>33</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=4&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>4</td>	<td>Transport</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>34</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=5&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>5</td>	<td>Artillery</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>1104</td>	<td>6/14/2013 7:13:28 PM</td></tr><tr>	<td>35</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=vehicle&amp;id=6&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">vehicle</a></td>	<td>6</td>	<td>GroundDefense</td>	<td>dbo.view_Leaders_Vehicles</td>	<td>get_leaders_vehicles</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>36</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=0&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>0</td>	<td>Assault</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>37</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=1&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>1</td>	<td>AssaultGrenade</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>38</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=2&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>2</td>	<td>Carbines</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>39</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=3&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>3</td>	<td>LightMachineGuns</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>40</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=4&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>4</td>	<td>SniperRifles</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>41</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=5&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>5</td>	<td>Pistols</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>42</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=6&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>6</td>	<td>ATAA</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>43</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=7&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>7</td>	<td>SubmachineGuns</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr><tr>	<td>44</td>	<td><a style="color:blue;" href="getleaderboard.aspx?type=weapon&amp;id=8&amp;pos=10&amp;before=9&amp;after=10&amp;debug=tx&amp;nocache=635068478830894541">weapon</a></td>	<td>8</td>	<td>Shotguns</td>	<td>dbo.view_Leaders_Weapons</td>	<td>get_leaders_weapons</td>	<td>0</td>	<td>1/1/0001 12:00:00 AM</td></tr></tbody></table>
</body></html>"""

@app.route('/SILLYREDIRECT')
def SILLYREDIRECT():
    headers={ 'content-type':'text/plain' ,'location':'http://github.com/thexgamelord/HeHeSPY'}
    return '',302,headers

#@app.route('/signup')
#def SecureSignup():
#    return redirect('https://google.com/', code=302)

@app.route('/image.asp')
def bf2img():
    lang = request.args.get('lang', 'English')
    print("bf2 image.asp for " + lang)
    return send_file(webroot_dir + '/BF2_Patch_1.50.exe')

@app.route('/<path:filename>')
def serve_file(filename):
    # Extract the actual file path without the query string
    actual_filename = request.path.strip('/')
    
    full_path = os.path.join(webroot_dir, actual_filename)
    html_path = full_path + '.html'
    #print(html_path)
    if os.path.exists(html_path):
        return send_file(html_path)
    
    
    if os.path.exists(full_path):
        if os.path.isdir(full_path):
            # If it's a directory, try to serve the index.html file
            index_path = os.path.join(full_path, 'index.html')
            if os.path.exists(index_path):
                return send_file(index_path)
            abort(404)  # No index file found
        else:
            return send_file(full_path)
    abort(404)  # File or directory not found

@app.route('/crashupload.aspx', methods=["POST"])
def parse_crash():  
    existing_files = [filename for filename in os.listdir('./web_private/crashuploads/') if filename.startswith('dmp_') and filename.endswith('.txt')]
    if existing_files:
        numbers = [int(filename.split('_')[1].split('.')[0]) for filename in existing_files]
        new_number = max(numbers) + 1
    else:
        new_number = 1

    filename = f"./web_private/crashuploads/dmp_{new_number}.txt"

    with open(filename, 'w') as file:
        file.write(f"------------------------------------------------\n")
        file.write(f"ProductID: {request.args.get('ProductID')}\n")
        file.write(f"VersionID: {request.args.get('VersionID')}\n")
        file.write(f"ProfileID: {request.args.get('ProfileID')}\n")
        file.write(f"DistID: {request.args.get('DistID')}\n")
        file.write(f"Code: {request.args.get('Code')}\n")
        file.write(f"Module: {request.args.get('Module')}\n")
        file.write(f"Address: {request.args.get('Address')}\n")
        file.write(f"Extra: {request.args.get('Extra')}\n")
        file.write(f"------------------------------------------------\n")
        file.close()

    return f"Crash dump uploaded"

def is_ip_allowed(ip):
    #return True
    pubip = get('https://api.ipify.org').content.decode('utf8')
    for item in ip_whitelist:
        if '/' in item:
            # This is a subnet, e.g., 192.168.1.0/24
            network, subnet = item.split('/')
            if ipaddress.ip_address(ip) in ipaddress.ip_network(item, strict=False):
                return True
            elif str(ipaddress.ip_address(ip)) in pubip:
                return True

        elif ip == item:
            return True
    return False

def is_ip_banned(ip):
    #return True
    for item in ip_blacklist:
        if '/' in item:
            # This is a subnet, e.g., 192.168.1.0/24
            network, subnet = item.split('/')
            if ipaddress.ip_address(ip) in ipaddress.ip_network(item, strict=False):
                return True

        elif ip == item:
            return True
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True, debug=True)
    #app.run(host='0.0.0.0', port=28900, threaded=True, debug=True)