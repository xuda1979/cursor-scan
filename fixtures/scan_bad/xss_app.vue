<template>
  <div>
    <h1>Dashboard</h1>

    <!-- Vue directives: v-html and :innerHTML write raw HTML into the DOM -->
    <section v-html="pageDescription"></section>
    <div :innerHTML="article.html"></div>

    <!-- Angular property bindings -->
    <div [innerHTML]="post.body"></div>
    <div [outerHTML]="card.template"></div>

    <!-- static content is inert: a hardcoded literal cannot be influenced -->
    <p v-html="'<b>fixed banner</b>'"></p>
    <!-- plain interpolation escapes -->
    <p>{{ username }}</p>
  </div>
</template>

<script setup>
const props = defineProps(['pageDescription', 'article', 'post', 'card']);
</script>
