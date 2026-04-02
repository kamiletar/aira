package org.aira.android.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavType
import androidx.navigation.compose.*
import androidx.navigation.navArgument
import org.aira.android.R
import org.aira.android.repository.AiraRepository
import org.aira.android.ui.screens.*

/**
 * Top-level navigation graph with bottom navigation bar.
 */
@Composable
fun AiraNavGraph(repository: AiraRepository?) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    Scaffold(
        bottomBar = {
            NavigationBar {
                bottomNavItems.forEach { item ->
                    NavigationBarItem(
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label) },
                        selected = currentDestination?.hierarchy?.any { it.route == item.route } == true,
                        onClick = {
                            navController.navigate(item.route) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Route.CONTACTS,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Route.CONTACTS) {
                ContactsScreen(
                    repository = repository,
                    onContactClick = { pubkey ->
                        navController.navigate("${Route.CHAT}/${pubkey.toHexString()}")
                    },
                    onAddContactClick = {
                        navController.navigate(Route.ADD_CONTACT)
                    }
                )
            }
            composable(
                route = "${Route.CHAT}/{pubkey}",
                arguments = listOf(navArgument("pubkey") { type = NavType.StringType })
            ) { backStackEntry ->
                val pubkey = backStackEntry.arguments?.getString("pubkey") ?: ""
                ChatScreen(repository = repository, contactPubkeyHex = pubkey)
            }
            composable(Route.ADD_CONTACT) {
                AddContactScreen(
                    repository = repository,
                    onContactAdded = { navController.popBackStack() }
                )
            }
            composable(Route.GROUPS) {
                GroupsScreen(
                    repository = repository,
                    onGroupClick = { groupId ->
                        navController.navigate("${Route.GROUP_CHAT}/${groupId.toHexString()}")
                    },
                    onCreateGroupClick = {
                        // TODO: navigate to create group screen
                    }
                )
            }
            composable(
                route = "${Route.GROUP_CHAT}/{groupId}",
                arguments = listOf(navArgument("groupId") { type = NavType.StringType })
            ) { backStackEntry ->
                val groupId = backStackEntry.arguments?.getString("groupId") ?: ""
                GroupChatScreen(repository = repository, groupIdHex = groupId)
            }
            composable(Route.SETTINGS) {
                SettingsScreen(
                    repository = repository,
                    onIdentityClick = { navController.navigate(Route.IDENTITY) }
                )
            }
            composable(Route.IDENTITY) {
                IdentityScreen(repository = repository)
            }
        }
    }
}

/** Navigation routes. */
object Route {
    const val CONTACTS = "contacts"
    const val CHAT = "chat"
    const val ADD_CONTACT = "add_contact"
    const val GROUPS = "groups"
    const val GROUP_CHAT = "group_chat"
    const val SETTINGS = "settings"
    const val IDENTITY = "identity"
}

/** Bottom navigation items. */
private data class BottomNavItem(
    val route: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
    val label: String
)

private val bottomNavItems = listOf(
    BottomNavItem(Route.CONTACTS, Icons.Default.People, "Contacts"),
    BottomNavItem(Route.GROUPS, Icons.Default.Group, "Groups"),
    BottomNavItem(Route.SETTINGS, Icons.Default.Settings, "Settings")
)

/** Convert ByteArray to hex string. */
private fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }
