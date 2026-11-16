<script>
  export let userBio;
  export let announcements;
</script>

<h1>Profile</h1>
<p>{userBio}</p>
<p>{@html userBio}</p>

<ul>
  {#each announcements as item}
    <li>{@html item.text}</li>
  {/each}
</ul>
