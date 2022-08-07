import { getAuth } from "firebase/auth";

const auth = getAuth();
auth.languageCode = firebase.auth().useDeviceLanguage();
// To apply the default browser preference instead of explicitly setting it.
// firebase.auth().useDeviceLanguage();