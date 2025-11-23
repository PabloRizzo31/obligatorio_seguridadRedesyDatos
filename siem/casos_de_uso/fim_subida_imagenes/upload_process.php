<?php
// Directorio donde se guardarán los archivos. Debe coincidir con el paso 1.
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$fileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

// --- 1. Verificación de Seguridad Básica ---

// Comprueba si el archivo ya existe
if (file_exists($target_file)) {
    echo "<p style='color:red;'>❌ Lo siento, el archivo ya existe.</p>";
    $uploadOk = 0;
}

// Limita el tamaño del archivo (ejemplo: 5MB)
if ($_FILES["fileToUpload"]["size"] > 5000000) {
    echo "<p style='color:red;'>❌ Lo siento, tu archivo es demasiado grande (máx. 5MB).</p>";
    $uploadOk = 0;
}

// Opcional: Permite solo ciertos formatos (ej. JPG, PNG, PDF)
if($fileType != "pdf" && $fileType != "jpg" && $fileType != "png" && $fileType != "jpeg") {
    // Si necesitas subir cualquier tipo de archivo, elimina esta verificación.
    // echo "<p style='color:red;'>❌ Lo siento, solo se permiten archivos JPG, JPEG, PNG y PDF.</p>";
    // $uploadOk = 0;
}

// --- 2. Intento de Subida ---

if ($uploadOk == 0) {
    echo "<p style='color:red;'>El archivo no fue subido debido a un error.</p>";
} else {
    // La función move_uploaded_file() es crucial, mueve el archivo temporal al destino final.
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "<h2>✅ ¡Subida Exitosa!</h2>";
        echo "<p>El archivo <strong>". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). "</strong> ha sido subido con éxito.</p>";
        echo "<p>Ruta en el servidor: /var/www/html/{$target_file}</p>";
        echo "<p>Puedes verlo aquí: <a href='{$target_file}'>http://tusitio.com/{$target_file}</a></p>";
    } else {
        echo "<h2>❌ Error de Subida</h2>";
        echo "<p>Lo siento, hubo un error desconocido al subir tu archivo.</p>";
        echo "<p><strong>Posible causa:</strong> El usuario `apache` no tiene permisos de escritura en la carpeta `uploads`.</p>";
    }
}
?>
