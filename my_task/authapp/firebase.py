from django.views.decorators.csrf import csrf_exempt
import firebase_admin
from firebase_admin import credentials, messaging
from django.http import JsonResponse
import json
from django.http import HttpResponse



cred = credentials.Certificate('authapp/ecomm-46ec0-firebase-adminsdk-q5ov2-c6bad93b96.json')
firebase_admin.initialize_app(cred)




@csrf_exempt
def send_notification(request):
    if request.method == 'POST':
        print("hello")
        data = json.loads(request.body)
        print(data)
        message = messaging.Message(
            notification=messaging.Notification(
                title=data.get('title'),
                body=data.get('body'),
            ),
            token=data.get('registration_id'),
        )
        response = messaging.send(message)
        return JsonResponse({'status': 'success', 'response': response})
    return JsonResponse({'status': 'failed', 'message': 'Invalid request'}, status=400)


def showFirebaseJS(request):
    data="""
        importScripts('https://www.gstatic.com/firebasejs/9.6.10/firebase-app-compat.js');
         importScripts('https://www.gstatic.com/firebasejs/9.6.10/firebase-messaging-compat.js');

         const firebaseConfig2 = {
            apiKey: "AIzaSyDM8II5LZKARXfCtKrkMq4n1wFH_Nidpr0",
            authDomain: "ecomm-46ec0.firebaseapp.com",
            databaseURL: "https://ecomm-46ec0-default-rtdb.asia-southeast1.firebasedatabase.app",
            projectId: "ecomm-46ec0",
            storageBucket: "ecomm-46ec0.appspot.com",
            messagingSenderId: "776601915913",
            appId: "1:776601915913:web:31d9364423f30bca155ed8",
         measurementId: "G-9MXN6EF4YN"
                                    };

         firebase.initializeApp(firebaseConfig2);

         const messaging2 = firebase.messaging();

         messaging2.onBackgroundMessage((payload) => {
         console.log('Received background message: ', payload);

         const notificationTitle = payload.notification.title;
         const notificationOptions = {
         body: payload.notification.body,
         icon: '/firebase-logo.png'
                                        };

         self.registration.showNotification(notificationTitle, notificationOptions);
                });
        """
    return HttpResponse(data, content_type="text/javascript")
