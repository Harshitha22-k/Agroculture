<?php
session_start();

require '../db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Function to sanitize user input
    function dataFilter($data) {
        return htmlspecialchars(stripslashes(trim($data)));
    }

    // Sanitize input data
    $name = dataFilter($_POST['name']);
    $mobile = dataFilter($_POST['mobile']);
    $user = dataFilter($_POST['uname']);
    $email = dataFilter($_POST['email']);
    $pass = password_hash(dataFilter($_POST['pass']), PASSWORD_BCRYPT);
    $hash = md5(rand(0, 1000));
    $category = dataFilter($_POST['category']);
    $addr = dataFilter($_POST['addr']);

    // Store sanitized data in session
    $_SESSION['Email'] = $email;
    $_SESSION['Name'] = $name;
    $_SESSION['Password'] = $pass;
    $_SESSION['Username'] = $user;
    $_SESSION['Mobile'] = $mobile;
    $_SESSION['Category'] = $category;
    $_SESSION['Hash'] = $hash;
    $_SESSION['Addr'] = $addr;
    $_SESSION['Rating'] = 0;

    // Validate mobile number length
    if (strlen($mobile) != 10) {
        $_SESSION['message'] = "Invalid Mobile Number !!!";
        header("location: error.php");
        exit();
    }

    // Check category and proceed with appropriate registration
    if ($category == 1) {
        $table = "farmer";
        $email_column = "femail";
        $name_column = "fname";
        $username_column = "fusername";
        $password_column = "fpassword";
        $hash_column = "fhash";
        $mobile_column = "fmobile";
        $address_column = "faddress";
        $id_column = "fid";
    } else {
        $table = "buyer";
        $email_column = "bemail";
        $name_column = "bname";
        $username_column = "busername";
        $password_column = "bpassword";
        $hash_column = "bhash";
        $mobile_column = "bmobile";
        $address_column = "baddress";
        $id_column = "bid";
    }

    // Check if user already exists
    $stmt = $conn->prepare("SELECT * FROM $table WHERE $email_column = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $_SESSION['message'] = "User with this email already exists!";
        header("location: error.php");
        exit();
    } else {
        // Insert new user
        $stmt = $conn->prepare("INSERT INTO $table ($name_column, $username_column, $password_column, $hash_column, $mobile_column, $email_column, $address_column) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sssssss", $name, $user, $pass, $hash, $mobile, $email, $addr);

        if ($stmt->execute()) {
            $_SESSION['Active'] = 1;
            $_SESSION['logged_in'] = true;

            // Retrieve user ID
            $stmt = $conn->prepare("SELECT $id_column FROM $table WHERE $username_column = ?");
            $stmt->bind_param("s", $user);
            $stmt->execute();
            $result = $stmt->get_result();
            $User = $result->fetch_assoc();
            $_SESSION['id'] = $User[$id_column];

            $_SESSION['message'] = "Hey!! Welcome to AgroCulture!";
            header("location: profile.php");
        } else {
            $_SESSION['message'] = "Registration failed!";
            header("location: error.php");
        }
    }
}
?>
