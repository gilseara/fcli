plugins { id("fcli.module-conventions") }

dependencies {
    val aviatorCommonRef = project.findProperty("fcliAviatorCommonRef") as String
    implementation(project(aviatorCommonRef))
    implementation("jakarta.xml.bind:jakarta.xml.bind-api:3.0.1")
    runtimeOnly("org.glassfish.jaxb:jaxb-runtime:3.0.2")
}
