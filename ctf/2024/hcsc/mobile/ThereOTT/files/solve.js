Java.perform(function() {
    var utilsjni = Java.use('hu.honeylab.hcsc.thereott.UtilsJNI')
    console.log(utilsjni.genSignature("POST", "/flag", "", "x-tott-app-id:hu.honeylab.hcsc.thereott,x-tott-app-name:thereott", "flag", "1714136717840"))
});