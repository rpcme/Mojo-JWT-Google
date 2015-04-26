# Mojo-JWT-Google
Easily create a JWT for Google authorization.



Changes in Version 0.02
-----------------------
Attempt to fix failed tests on cpantesters that could not be replicated
Fix a couple documentation typos
Change claims construction and remove Time::HiRes dependency based on new
  Mojo::JWT set_iat method.
Remove Mojolicious dependency as parent has it.
Remove strictures dependency since Mojo::Base controls how strict you are.

Changes in Version 0.01
-----------------------
Initial implementation.
