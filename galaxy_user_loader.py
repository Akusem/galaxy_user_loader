import os
import re
import sys
import ssl
import time
import atexit
import secrets
import smtplib
from typing import List, Tuple
from datetime import datetime
from email.message import EmailMessage
from bioblend import galaxy, ConnectionError
from InquirerPy import inquirer
from InquirerPy.validator import ValidationError, PathValidator
from rich import print
from rich.console import Console
from rich.traceback import install

# URL of the Galaxy instance
GALAXY_URL = "http://127.0.0.1:8080"
# Admin API key, can be generated in user preferences > Manage API Key
API_KEY = ""
# When creating new accounts, a password is randomly generated, this define it's length
PASSWORD_LENGTH = 16
# All the created users and their password can be stored in a file.
# This define the name of the file, it should contain a '{}' where the date will be put using format
PASSWORD_FILE = "./galaxy_user_{}.txt"

# Email SMTP Host URL
SMTP_HOST = "smtp-mail.outlook.com"
SMTP_PORT = 587
# Sender email credential
MAIL = ""
MAIL_PASSWORD = ""
# When creating a new account, galaxy_user_loader.py will send an email to the user with his credential.
# Mail subject
LOGIN_MAIL_SUBJECT = "Galaxy Account creation"
# Mail content sended to new users, will use HTML and text (FALLBACK)
# Need to contain two '{}', as the script will use LOGIN_MAIL_BODY_HTML.format(user_mail, user_password)
# So use {} in good order
LOGIN_MAIL_BODY_HTML = (
    f"Your student account for <a href='{GALAXY_URL}'>Galaxy</a> have been created.<br />"
    "Your login information are: <br />"
    "Login: {}\n <br />"
    "Password: {}\n <br />"
    "<br />"
    "<b>Please change your password on first login for security</b>"
)
# If email client doesn't accept HTML, fallback on this text version
LOGIN_MAIL_BODY_FALLBACK = (
    "Your student account for Galaxy have been created.\n"
    "Your login information are:\n"
    "Login: {}\n"
    "Password: {}\n\n"
    f"You can access Galaxy at {GALAXY_URL}, and think to change your password on first login for security"
)


def main():
    # All Traceback handled by Rich
    install(show_locals=True)
    c = Console()
    c.print(f"[bold]Launching Galaxy user loader[/]")
    c.print(f"It will contact this [italic green]{GALAXY_URL}[/] instance")
    c.print(f"And use this key: [italic blue]{API_KEY}[/]")
    c.print(
        "If not valid, modify the [magenta]GALAXY_URL[/]"
        " and [magenta]API_KEY[/] constant in the file"
    )
    choice = inquirer.select(
        "What do you want to do ?",
        [
            "Add new Galaxy users",
            "Purge Galaxy users (delete account and data)",
            "Resend Users info from password file",
        ],
    ).execute()
    if choice == "Add new Galaxy users":
        add_users(c)
    elif choice == "Purge Galaxy users (delete account and data)":
        purge_users_info(c)
    elif choice == "Resend Users info from password file":
        resend_users_info(c)


def add_users(c: Console):
    emails = get_emails("Path to file with new users emails:")
    gi = create_galaxy_instance()
    email_server = EmailServer(c=c)
    c.print(
        "[yellow]Do you want to save the users password in a file ?\n"
        "I recommend doing it for the [bold green]first times[/] as if the emailing fail, "
        "the [bold red]passwords will be lost[/] and you will have to reset them manually for each users"
    )
    save_password = inquirer.confirm("Save passwords ?", default=True).execute()
    if save_password:
        password_file = PASSWORD_FILE.format(datetime.now().strftime("%Y_%m_%d-%I_%M"))
        c.print(f"[bold magenta]Will save password in file {password_file}")
        password_file = open(password_file, "w")
    else:
        c.print("[bold magenta]Will not save password")
    with c.status(f"[bold green] creating accounts"):
        for email in emails:
            if already_have_galaxy_account(gi, email):
                c.print(f"[italic green]{email}[/] already have an account on Galaxy")
                continue
            if already_have_a_deleted_galaxy_account(gi, email):
                c.print(
                    f"[italic green]{email}[/] have a [bold red]deleted[/] account but still present in Galaxy"
                    f", you can restore/purge it from {os.path.join(GALAXY_URL, 'admin/users')} as admin"
                )
                continue
            username = generate_username(email)
            password = generate_password()
            create_galaxy_account(gi, username, email, password)
            c.print(f"Galaxy user [italic green]{email}[/] created :white_check_mark:")
            if save_password:
                password_file.write(f"{email} : {password}\n")
            email_server.send_login_info(
                email,
                password,
                success_message=f"Mail send succesfully to [italic green]{email}[/]",
            )

        time.sleep(1)
    c.print("[bold green]All accounts created/processed !")


def get_emails(message: str) -> List[str]:
    """Ask for path to emails file and parse it.
    Need to be with one email by line and without empty line.

    Args:
        message (str): Message asking for the emails file

    Returns:
        List[str]: A list of emails
    """
    filepath = inquirer.filepath(
        message,
        long_instruction="One email by line, without empty line",
        validate=UsersFileValidator(is_file=True),
    ).execute()
    return get_emails_from_file(filepath)


def get_emails_from_file(filepath: str) -> List[str]:
    """Get emails from a file formated with one email by line
    and no empty line

    Args:
        filepath (str): path to the file containing emails

    Returns:
        List[str]: A list of emails
    """
    file = open(filepath, "r")
    return [email.strip() for email in file if email]


def create_galaxy_instance() -> galaxy.GalaxyInstance:
    """Create and verify validity of a GalaxyInstance

    Returns:
        galaxy.GalaxyInstance: A GalaxyInstance ready to access Galaxy
    """
    gi = galaxy.GalaxyInstance(url=GALAXY_URL, key=API_KEY)
    test_galaxy_connection(gi)
    return gi


def test_galaxy_connection(galaxy_instance: galaxy.GalaxyInstance):
    """Verify a GalaxyInstance work correctly

    Args:
        galaxy_instance (galaxy.GalaxyInstance): The GalaxyInstance to test

    Raises:
        Exception: Galaxy address not valid
        Exception: API Key not valid
        error: Other connection Error to Galaxy
    """
    try:
        galaxy_instance.users.get_current_user()
    except ConnectionError as error:
        if error.status_code == 404 or "Max retries exceeded" in error.args[0]:
            print("[bold red] Galaxy Address is not valid, aborting.")
            sys.exit(1)
        elif "Provided API key is not valid." in error.body:
            print("[bold red] Provided API key is not valid, aborting.")
            sys.exit(1)
        elif "Provided API key has expired." in error.body:
            print("[bold red] Provided API key is has expired, aborting.")
            sys.exit(1)
        else:
            raise error


def already_have_galaxy_account(gi: galaxy.GalaxyInstance, email: str) -> bool:
    users = gi.users.get_users(f_email=email)
    return True if users else False


def already_have_a_deleted_galaxy_account(
    gi: galaxy.GalaxyInstance, email: str
) -> bool:
    deleted_users = gi.users.get_users(f_email=email, deleted=True)
    if deleted_users:
        # If purged consider we can recreate an account so return False
        if user_is_purged(gi, deleted_users[0]):
            return False
        return True
    else:
        return False


def user_is_purged(gi: galaxy.GalaxyInstance, user_info):
    info = gi.users.show_user(user_info["id"], deleted=True)
    return info["purged"]


def generate_username(email: str) -> str:
    """Take text before domain in email to generate username

    Args:
        email (str): Email used to create account

    Returns:
        str: An username
    """
    return email.split("@")[0]


def generate_password(length=PASSWORD_LENGTH) -> str:
    """Generate password using python integrated library

    Args:
        length (int, optional): Length of the password to create. Defaults to PASSWORD_LENGTH.

    Returns:
        str: A Password
    """
    return secrets.token_urlsafe(length)


def create_galaxy_account(
    gi: galaxy.GalaxyInstance, username: str, email: str, password: str
):
    """Create a Galaxy account using bioblend users.create_local_user function

    Args:
        gi (galaxy.GalaxyInstance): A Galaxy instance to modify galaxy
        username (str): New user username
        email (str): New user email (used for login)
        password (str): New user password

    Returns:
        Dict: All info from the created user
    """
    return gi.users.create_local_user(username, email, password)


def purge_users_info(c: Console):
    emails = get_emails("Path to file with users to purge emails:")
    confirm = inquirer.confirm(
        f"Are you sure you want to permanaly delete users and all theirs data: {', '.join(emails)}"
    ).execute()
    if not confirm:
        c.print("[bold red] Aborting purge")
        sys.exit(0)
    gi = create_galaxy_instance()
    ids = get_users_id_by_mails(gi, emails)
    with c.status(f"[bold green] Purging account"):
        for id, email in zip(ids, emails):
            gi.users.delete_user(user_id=id, purge=True)
            c.print(
                f"User [italic green]{email}[/] (id: [italic blue]{id}[/]) [bold red]purged[/] from Galaxy"
            )
        c.print("[bold green]All accounts [bold red]purged[/] !")


def get_users_id_by_mails(gi: galaxy.GalaxyInstance, emails: List[str]) -> List[str]:
    """From a list of users email, retrieve their internal galaxy IDs

    Args:
        gi (galaxy.GalaxyInstance): A Galaxy instance used to access galaxy
        emails (List[str]): A list of users emails

    Returns:
        List[str]: A list of users ID
    """
    ids = [gi.users.get_users(f_email=email) for email in emails]
    ids_deleted = [gi.users.get_users(f_email=email, deleted=True) for email in emails]
    all_ids = ids + ids_deleted
    return [id[0]["id"] for id in all_ids if id]


def resend_users_info(c: Console):
    """Reading a file with an email and password by line, resend login info to new users

    Args:
        c (Console): Rich console object, used to add text in synchro with the loading spinner
    """
    filepath = inquirer.filepath(
        "Path to password file:",
        long_instruction="One email and password, separated by ':', by line, without empty line",
        validate=UsersFileValidator(is_file=True, is_password_file=True),
    ).execute()
    passwords_info = get_passwords_from_file(filepath)
    email_server = EmailServer(c=c)
    with c.status(f"[bold green] Sending users login information"):
        for user in passwords_info:
            email_server.send_login_info(
                user[0],
                user[1],
                success_message=f":white_check_mark: Mail send succesfully to [italic green]{user[0]}[/]",
            )
    c.print(f"[bold green]Users info processed !")


def get_passwords_from_file(filepath: str) -> List[Tuple[str, str]]:
    """Reading a file with an email and password by line separated by a ':'
    return a List of tuple containing the email and password

    Args:
        filepath (str): Path to password file

    Returns:
        List[Tuple[str, str]]: List of users mail and password in tuple
    """
    pw = []
    for line in open(filepath, "r"):
        email, password = line.split(" : ")
        pw.append((email, password))
    return pw


class UsersFileValidator(PathValidator):
    def __init__(
        self,
        message: str = "Input is not a valid path",
        is_file: bool = False,
        is_dir: bool = False,
        is_password_file: bool = False,
    ) -> None:
        super().__init__(message, is_file, is_dir)
        self.is_password_file = is_password_file

    @staticmethod
    def valid_email(email: str) -> bool:
        regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        if re.fullmatch(regex, email):
            return True
        else:
            return False

    def validate(self, document) -> None:
        # Validate file is existing
        super().validate(document)
        # Verify it's one email by line
        if not self.is_password_file:
            self.validate_email_file(document)
        else:
            self.validate_password_file(document)

    def validate_email_file(self, document):
        emails = []
        file = open(document.text)
        for i, email in enumerate(file):
            email = email.strip()
            if not self.valid_email(email):
                # Verify number of mail on the same line
                if email.count("@") > 1:
                    raise ValidationError(
                        message=f"Multiple Emails present on line {i+1}",
                        cursor_position=document.cursor_position,
                    )
                raise ValidationError(
                    message=f"Email {email} line {i+1} is not valid",
                    cursor_position=document.cursor_position,
                )
            else:
                emails.append(email)
        # Verify duplicate aren't present
        if len(emails) != len(set(emails)):
            raise ValidationError(
                message="Duplicate email are present, please clean input file"
            )

    def validate_password_file(self, document):
        file = open(document.text)
        for i, line in enumerate(file):
            if not ":" in line:
                raise ValidationError(
                    message=(
                        f"No separator ':' at line {i+1}, "
                        "is it a password file generated by this script ?"
                    ),
                    cursor_position=document.cursor_position,
                )
            email, _ = line.split(" : ")
            if not self.valid_email(email):
                raise ValidationError(
                    message=f"Email {email} line {i+1} is not valid",
                    cursor_position=document.cursor_position,
                )


class EmailServer:
    def __init__(
        self,
        smtp_host: str = SMTP_HOST,
        smtp_port: int = SMTP_PORT,
        user: str = MAIL,
        password: str = MAIL_PASSWORD,
        c: Console = None,
    ) -> None:
        self.user = user
        self.c = c if c else Console()
        # Ensure the connection is closed with the program
        atexit.register(self.close)

        try:
            with self.c.status(f"[bold green] Connecting to email server {smtp_host}"):
                context = ssl.create_default_context()
                self.server = smtplib.SMTP(smtp_host, smtp_port)
                self.server.ehlo()
                self.server.starttls(context=context)
                self.server.ehlo()
                self.server.login(self.user, password)
        except Exception as error:
            self.c.print(
                f"Couldn't connect to [italic green]SMTP server[/] due to: {error}"
            )

    def send_login_info(
        self,
        email: str,
        password: str,
        subject=LOGIN_MAIL_SUBJECT,
        body_html=LOGIN_MAIL_BODY_HTML,
        body_fallback=LOGIN_MAIL_BODY_FALLBACK,
        success_message="",
    ):
        msg = EmailMessage()
        msg["From"] = self.user
        msg["Subject"] = subject
        msg["To"] = email
        # Fallback if the HTML is not supported
        msg.set_content(body_fallback.format(email, password))
        # Set mail content in HTML
        msg.add_alternative(body_html.format(email, password), subtype="html")
        try:
            self.server.send_message(msg)
            self.c.print(success_message)
        except Exception as error:
            self.c.print(
                f":warning: [yellow]Couldn't send email to[/] [italic green]{email}[/], error: {error}"
            )

    def close(self):
        self.server.close()


if __name__ == "__main__":
    main()
