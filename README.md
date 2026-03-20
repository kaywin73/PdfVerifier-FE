Modern users (using import) will get the 



.es.js

&#x20;version.

Legacy users (using require or <script> tags) will get the 



.umd.js

&#x20;version.

What to include in your "Distribution Package":

If you are sending this SDK to someone else, you should provide the entire dist/ folder. It contains everything they need:





pdf-verifier-sdk.es.js

: For modern apps.



pdf-verifier-sdk.umd.js

: For simple websites.

Which one should they use?

If they are building a modern web app (like with React, Vue, or Vite): Tell them to use 



.es.js

.

If they just want to drop a single file into an old HTML page: Tell them to use 



.umd.js

.

